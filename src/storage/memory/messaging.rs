//! `MessagingStore` for the in-memory backend: pushers, relations, reports,
//! OpenID, user directory, threads, search.

use std::collections::BTreeMap;

use async_trait::async_trait;

use super::{now_ms, MemoryStorage, RelationInternal, ReportInternal};
use crate::events::{ev_sender, ev_type};
use crate::search_match::event_matches_search_term;
use crate::storage::interface::{
    AnnotationCount, Direction, EventRecord, MessagingStore, RelatedEvents, SearchResults,
    StreamEventRecord, ThreadInclude, ThreadRoots, ThreadSummary, TokenUser, UserDirectoryEntry,
};
use crate::types::identifiers::{EventId, RoomId, Timestamp, UserId};
use crate::types::push::Pusher;

/// Read `room_id` off a stored event.
fn event_room_id(event: &serde_json::Value) -> Option<&str> {
    event.get("room_id").and_then(serde_json::Value::as_str)
}

#[async_trait]
impl MessagingStore for MemoryStorage {
    async fn get_pushers(&self, user_id: &UserId) -> Vec<Pusher> {
        self.read()
            .pushers
            .get(user_id.as_str())
            .cloned()
            .unwrap_or_default()
    }

    async fn set_pusher(&self, user_id: &UserId, pusher: Pusher) {
        let mut s = self.write();
        let list = s.pushers.entry(user_id.to_string()).or_default();
        match list
            .iter_mut()
            .find(|p| p.app_id == pusher.app_id && p.pushkey == pusher.pushkey)
        {
            Some(existing) => *existing = pusher,
            None => list.push(pusher),
        }
    }

    async fn delete_pusher(&self, user_id: &UserId, app_id: &str, pushkey: &str) {
        if let Some(list) = self.write().pushers.get_mut(user_id.as_str()) {
            list.retain(|p| !(p.app_id == app_id && p.pushkey == pushkey));
        }
    }

    async fn delete_pusher_by_key(&self, app_id: &str, pushkey: &str) {
        for list in self.write().pushers.values_mut() {
            list.retain(|p| !(p.app_id == app_id && p.pushkey == pushkey));
        }
    }

    async fn store_relation(
        &self,
        event_id: &EventId,
        room_id: &RoomId,
        rel_type: &str,
        target_event_id: &EventId,
        key: Option<&str>,
    ) {
        let mut s = self.write();
        let Some((sender, event_type)) = s
            .events_by_id
            .get(event_id.as_str())
            .map(|e| (ev_sender(e).to_string(), ev_type(e).to_string()))
        else {
            return;
        };
        let stream_pos = s
            .room_timeline
            .get(room_id.as_str())
            .and_then(|tl| tl.iter().find(|e| e.event_id == event_id.as_str()))
            .map(|e| e.stream_pos)
            .unwrap_or(s.stream_counter);
        s.relations
            .entry(target_event_id.to_string())
            .or_default()
            .push(RelationInternal {
                event_id: event_id.to_string(),
                rel_type: rel_type.to_string(),
                key: key.map(str::to_string),
                sender,
                event_type,
                stream_pos,
            });
    }

    async fn get_related_events(
        &self,
        room_id: &RoomId,
        event_id: &EventId,
        rel_type: Option<&str>,
        event_type: Option<&str>,
        limit: Option<usize>,
        from: Option<&str>,
        direction: Direction,
    ) -> RelatedEvents {
        let limit = limit.unwrap_or(50);
        let s = self.read();
        let mut relations: Vec<&RelationInternal> = s
            .relations
            .get(event_id.as_str())
            .map(|v| v.iter().collect())
            .unwrap_or_default();
        if let Some(rt) = rel_type {
            relations.retain(|r| r.rel_type == rt);
        }
        if let Some(et) = event_type {
            relations.retain(|r| r.event_type == et);
        }
        relations.sort_by(|a, b| match direction {
            Direction::Forward => a.stream_pos.cmp(&b.stream_pos),
            Direction::Backward => b.stream_pos.cmp(&a.stream_pos),
        });
        if let Some(from_pos) = from.and_then(|f| f.parse::<i64>().ok()) {
            let start = relations.iter().position(|r| match direction {
                Direction::Forward => r.stream_pos > from_pos,
                Direction::Backward => r.stream_pos < from_pos,
            });
            relations = match start {
                Some(i) => relations.split_off(i),
                None => Vec::new(),
            };
        }
        let sliced: Vec<&RelationInternal> = relations.into_iter().take(limit).collect();
        let events = sliced
            .iter()
            .filter_map(|r| {
                let event = s.events_by_id.get(&r.event_id)?;
                if event_room_id(event) != Some(room_id.as_str()) {
                    return None;
                }
                Some(EventRecord {
                    event: (**event).clone(),
                    event_id: r.event_id.clone().into(),
                })
            })
            .collect();
        let next_batch = if sliced.len() == limit && !sliced.is_empty() {
            sliced.last().map(|r| r.stream_pos.to_string())
        } else {
            None
        };
        RelatedEvents { events, next_batch }
    }

    async fn get_annotation_counts(&self, event_id: &EventId) -> Vec<AnnotationCount> {
        let s = self.read();
        let mut counts: BTreeMap<String, AnnotationCount> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        if let Some(rels) = s.relations.get(event_id.as_str()) {
            for ann in rels
                .iter()
                .filter(|r| r.rel_type == "m.annotation" && r.key.is_some())
            {
                let key = ann.key.clone().unwrap();
                let map_key = format!("{}\u{1f}{}", ann.event_type, key);
                match counts.get_mut(&map_key) {
                    Some(c) => c.count += 1,
                    None => {
                        order.push(map_key.clone());
                        counts.insert(
                            map_key,
                            AnnotationCount {
                                annotation_type: ann.event_type.clone(),
                                key,
                                count: 1,
                            },
                        );
                    }
                }
            }
        }
        order
            .into_iter()
            .filter_map(|k| counts.remove(&k))
            .collect()
    }

    async fn get_latest_edit(&self, event_id: &EventId, sender: &UserId) -> Option<EventRecord> {
        let s = self.read();
        let rels = s.relations.get(event_id.as_str())?;
        let latest = rels
            .iter()
            .filter(|r| r.rel_type == "m.replace" && r.sender == sender.as_str())
            .max_by_key(|r| r.stream_pos)?;
        let event = s.events_by_id.get(&latest.event_id)?;
        Some(EventRecord {
            event: (**event).clone(),
            event_id: latest.event_id.clone().into(),
        })
    }

    async fn get_thread_summary(
        &self,
        event_id: &EventId,
        user_id: &UserId,
    ) -> Option<ThreadSummary> {
        let s = self.read();
        let rels = s.relations.get(event_id.as_str())?;
        let mut replies: Vec<&RelationInternal> =
            rels.iter().filter(|r| r.rel_type == "m.thread").collect();
        if replies.is_empty() {
            return None;
        }
        replies.sort_by_key(|r| r.stream_pos);
        let latest = replies.last().unwrap();
        let latest_event = s.events_by_id.get(&latest.event_id)?;
        Some(ThreadSummary {
            latest_event: EventRecord {
                event: (**latest_event).clone(),
                event_id: latest.event_id.clone().into(),
            },
            count: replies.len() as i64,
            current_user_participated: replies.iter().any(|r| r.sender == user_id.as_str()),
        })
    }

    async fn store_report(
        &self,
        user_id: &UserId,
        room_id: &RoomId,
        event_id: &EventId,
        score: Option<i64>,
        reason: Option<&str>,
    ) {
        self.write().reports.push(ReportInternal {
            user_id: user_id.to_string(),
            room_id: room_id.to_string(),
            event_id: event_id.to_string(),
            score,
            reason: reason.map(str::to_string),
            ts: now_ms(),
        });
    }

    async fn store_open_id_token(&self, token: &str, user_id: &UserId, expires_at: Timestamp) {
        self.write().open_id_tokens.insert(
            token.to_string(),
            TokenUser {
                user_id: user_id.clone(),
                expires_at,
            },
        );
    }

    async fn get_open_id_token(&self, token: &str) -> Option<TokenUser> {
        self.read().open_id_tokens.get(token).cloned()
    }

    async fn search_user_directory(
        &self,
        search_term: &str,
        limit: usize,
    ) -> Vec<UserDirectoryEntry> {
        let term = search_term.to_lowercase();
        let s = self.read();
        let mut results = Vec::new();
        for user in s.users_by_id.values() {
            if user.is_deactivated {
                continue;
            }
            let match_id = user.user_id.as_str().to_lowercase().contains(&term);
            let match_name = user
                .displayname
                .as_deref()
                .map(|d| d.to_lowercase().contains(&term))
                .unwrap_or(false);
            if match_id || match_name {
                results.push(UserDirectoryEntry {
                    user_id: user.user_id.clone(),
                    display_name: user.displayname.clone(),
                    avatar_url: user.avatar_url.clone(),
                });
            }
            if results.len() >= limit {
                break;
            }
        }
        results
    }

    async fn get_thread_roots(
        &self,
        room_id: &RoomId,
        user_id: &UserId,
        include: ThreadInclude,
        limit: usize,
        from: Option<&str>,
    ) -> ThreadRoots {
        let s = self.read();
        // target_event_id -> (max stream pos, participated)
        let mut roots: Vec<(String, i64, bool)> = Vec::new();
        for (target_id, rels) in &s.relations {
            let thread_replies: Vec<&RelationInternal> =
                rels.iter().filter(|r| r.rel_type == "m.thread").collect();
            if thread_replies.is_empty() {
                continue;
            }
            let Some(target_event) = s.events_by_id.get(target_id) else {
                continue;
            };
            if event_room_id(target_event) != Some(room_id.as_str()) {
                continue;
            }
            let max_pos = thread_replies.iter().map(|r| r.stream_pos).max().unwrap();
            let participated = thread_replies.iter().any(|r| r.sender == user_id.as_str());
            roots.push((target_id.clone(), max_pos, participated));
        }
        if include == ThreadInclude::Participated {
            roots.retain(|(_, _, p)| *p);
        }
        roots.sort_by_key(|r| std::cmp::Reverse(r.1));
        if let Some(from_pos) = from.and_then(|f| f.parse::<i64>().ok()) {
            let start = roots.iter().position(|(_, pos, _)| *pos < from_pos);
            roots = match start {
                Some(i) => roots.split_off(i),
                None => Vec::new(),
            };
        }
        let sliced: Vec<(String, i64, bool)> = roots.into_iter().take(limit).collect();
        let events = sliced
            .iter()
            .filter_map(|(eid, _, _)| {
                s.events_by_id.get(eid).map(|e| EventRecord {
                    event: (**e).clone(),
                    event_id: eid.clone().into(),
                })
            })
            .collect();
        let next_batch = if sliced.len() == limit && !sliced.is_empty() {
            sliced.last().map(|(_, pos, _)| pos.to_string())
        } else {
            None
        };
        ThreadRoots { events, next_batch }
    }

    async fn search_room_events(
        &self,
        room_ids: &[RoomId],
        search_term: &str,
        keys: &[String],
        limit: usize,
        from: Option<&str>,
    ) -> SearchResults {
        let s = self.read();
        // Gather all timeline entries across the rooms, newest first.
        let mut entries: Vec<&super::TimelineEntry> = room_ids
            .iter()
            .filter_map(|rid| s.room_timeline.get(rid.as_str()))
            .flat_map(|tl| tl.iter())
            .collect();
        entries.sort_by_key(|e| std::cmp::Reverse(e.stream_pos));

        let mut all_matches: Vec<StreamEventRecord> = Vec::new();
        for entry in entries {
            let Some(event) = s.events_by_id.get(&entry.event_id) else {
                continue;
            };
            if event_matches_search_term(event, keys, search_term) {
                all_matches.push(StreamEventRecord {
                    event: (**event).clone(),
                    event_id: entry.event_id.clone().into(),
                    stream_pos: entry.stream_pos,
                });
            }
        }

        // Paginate (strix `paginateSearchMatches`): newest-first, page after `from`.
        let count = all_matches.len() as i64;
        let from_pos = from.and_then(|f| f.parse::<i64>().ok());
        let page_source: Vec<StreamEventRecord> = match from_pos {
            Some(fp) => all_matches
                .into_iter()
                .filter(|m| m.stream_pos < fp)
                .collect(),
            None => all_matches,
        };
        let events: Vec<StreamEventRecord> = page_source.into_iter().take(limit).collect();
        let next_batch = events.last().map(|e| e.stream_pos.to_string());
        SearchResults {
            events,
            count,
            next_batch,
        }
    }
}
