"""Content retention and separate appeal/AI-improvement permissions.

The contribution store is a restricted holding area, not a training dataset.
No exporter or training job may use it while platform permission is unresolved.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

APPEAL_PRIVACY_VERSION = "2026-10-01-appeals-v1"
AI_NOTICE_VERSION = "2026-10-01-ai-improvement-v1"
AI_TRAINING_ENABLED = False
AI_CONTRIBUTION_DAYS = 90
CONTENT_DAYS = 30
APPEAL_DAYS = 10
AUTOMATED_EVENTS = frozenset({"automatic_deletion", "automatic_deletion_failed", "moderation_review_pending"})
CONTENT_KEYS = frozenset({"original_content", "original_message", "message_content", "content", "ai_thinking", "before_content", "after_content", "attachments", "image_urls", "images"})


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


class AppealPrivacyStore:
    def __init__(self, database):
        self.database = database
        self.connection = database.connection
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS moderated_content_lifecycles (
                server_id TEXT NOT NULL, message_id TEXT NOT NULL, user_id TEXT NOT NULL,
                decided_at TEXT NOT NULL, purged_at TEXT,
                PRIMARY KEY(server_id,message_id)
            );
            CREATE TABLE IF NOT EXISTS appeal_privacy_consents (
                appeal_id INTEGER PRIMARY KEY REFERENCES appeals(id) ON DELETE CASCADE,
                server_id TEXT NOT NULL, user_id TEXT NOT NULL,
                privacy_version TEXT NOT NULL, privacy_accepted_at TEXT NOT NULL,
                ai_improvement_opt_in INTEGER NOT NULL DEFAULT 0,
                ai_notice_version TEXT, ai_consented_at TEXT, ai_withdrawn_at TEXT
            );
            CREATE TABLE IF NOT EXISTS appeal_ai_contributions (
                appeal_id INTEGER PRIMARY KEY REFERENCES appeals(id) ON DELETE CASCADE,
                server_id TEXT NOT NULL, user_id TEXT NOT NULL, message_id TEXT NOT NULL,
                original_content TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                notice_version TEXT NOT NULL, appeal_outcome TEXT NOT NULL,
                review_status TEXT NOT NULL DEFAULT 'not_approved_for_training'
            );
            CREATE TABLE IF NOT EXISTS appeal_content_disposals (
                appeal_id INTEGER PRIMARY KEY REFERENCES appeals(id) ON DELETE CASCADE,
                deleted_at TEXT NOT NULL, reason TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS moderated_content_lifecycle_age
                ON moderated_content_lifecycles(purged_at,decided_at);
        """)
        if not self.connection.execute("SELECT 1 FROM app_metadata WHERE key='appeal_content_lifecycles_v1'").fetchone():
            for row in self.connection.execute("SELECT server_id,user_id,message_id,created_at FROM warnings WHERE source='automatic' AND message_id IS NOT NULL").fetchall():
                self.register(*row)
            marks = ','.join('?' for _ in AUTOMATED_EVENTS)
            for row in self.connection.execute(f"SELECT server_id,user_id,message_id,created_at FROM moderation_events WHERE event_type IN ({marks}) AND message_id IS NOT NULL AND user_id IS NOT NULL", tuple(AUTOMATED_EVENTS)).fetchall():
                self.register(*row)
            self.connection.execute("INSERT INTO app_metadata(key,value) VALUES ('appeal_content_lifecycles_v1','1')")
        self.connection.commit()

    def register(self, server_id: str, user_id: str, message_id: str | None, decided_at: str) -> None:
        if not message_id or not user_id:
            return
        self.connection.execute("""INSERT INTO moderated_content_lifecycles(server_id,user_id,message_id,decided_at)
            VALUES (?,?,?,?) ON CONFLICT(server_id,message_id) DO UPDATE SET
            decided_at=MIN(moderated_content_lifecycles.decided_at,excluded.decided_at)""",
            (server_id,user_id,message_id,decided_at))

    def message_was_purged(self, server_id: str, message_id: str | None) -> bool:
        return bool(message_id and self.connection.execute(
            'SELECT 1 FROM moderated_content_lifecycles WHERE server_id=? AND message_id=? AND purged_at IS NOT NULL',
            (server_id, message_id),
        ).fetchone())

    def case_content_closed(self, server_id: str, reference: str, user_id: str) -> bool:
        if self.connection.execute('SELECT 1 FROM appeals a JOIN appeal_content_disposals d ON d.appeal_id=a.id WHERE a.server_id=? AND a.case_reference=?', (server_id,reference)).fetchone():
            return True
        source = self.source({'server_id':server_id,'case_reference':reference,'user_id':user_id})
        return bool(source and self.message_was_purged(server_id, source['message_id']))

    def source(self, appeal: dict[str, Any]) -> dict[str, Any] | None:
        case = self.connection.execute("SELECT * FROM moderation_cases WHERE server_id=? AND reference_id=? AND user_id=?", (appeal['server_id'],appeal['case_reference'],appeal['user_id'])).fetchone()
        if case is None:
            return None
        if case['source_type'] == 'warning':
            warning = self.connection.execute("SELECT * FROM warnings WHERE id=? AND server_id=? AND user_id=?", (case['source_id'],appeal['server_id'],appeal['user_id'])).fetchone()
            if warning is None:
                return None
            return {'message_id':warning['message_id'], 'content':warning['original_content'], 'automatic':warning['source']=='automatic' and bool(json.loads(warning['scores_json'] or '{}')), 'case':dict(case)}
        event = self.connection.execute("SELECT * FROM moderation_events WHERE id=? AND server_id=? AND user_id=?", (case['source_id'],appeal['server_id'],appeal['user_id'])).fetchone()
        if event is None:
            return None
        details=json.loads(event['details_json'])
        if details.get('warning_id'):
            warning=self.connection.execute("SELECT * FROM warnings WHERE id=? AND server_id=? AND user_id=?", (details['warning_id'],appeal['server_id'],appeal['user_id'])).fetchone()
            if warning:
                return {'message_id':warning['message_id'],'content':warning['original_content'],'automatic':event['event_type'] in AUTOMATED_EVENTS or (warning['source']=='automatic' and bool(json.loads(warning['scores_json'] or '{}'))),'case':dict(case)}
        return {'message_id':event['message_id'],'content':details.get('original_content'),'automatic':event['event_type'] in AUTOMATED_EVENTS,'case':dict(case)}

    def public_status(self, appeal: dict[str, Any]) -> dict[str, Any]:
        row=self.connection.execute('SELECT * FROM appeal_privacy_consents WHERE appeal_id=?', (appeal['id'],)).fetchone()
        source=self.source(appeal)
        contribution=self.connection.execute('SELECT expires_at FROM appeal_ai_contributions WHERE appeal_id=?', (appeal['id'],)).fetchone()
        disposed=self.connection.execute('SELECT deleted_at FROM appeal_content_disposals WHERE appeal_id=?', (appeal['id'],)).fetchone()
        return {
            'policy_version':APPEAL_PRIVACY_VERSION,
            'ai_notice_version':AI_NOTICE_VERSION,
            'ai_improvement_eligible':bool(source and source['automatic'] and source['message_id'] and source['content']),
            'ai_improvement_opt_in':bool(row and row['ai_improvement_opt_in']),
            'ai_training_enabled':AI_TRAINING_ENABLED,
            'ai_contribution_days':AI_CONTRIBUTION_DAYS,
            'ai_contribution_expires_at':contribution['expires_at'] if contribution else None,
            'content_deleted_at':disposed['deleted_at'] if disposed else None,
            'appeal_deadline':(parse_time(appeal['submitted_at'])+timedelta(days=APPEAL_DAYS)).isoformat() if appeal.get('submitted_at') else None,
        }

    def record(self, appeal: dict[str, Any], privacy_version: str, ai_opt_in: bool | None) -> None:
        if privacy_version != APPEAL_PRIVACY_VERSION:
            raise ValueError('The appeal privacy notice has changed. Refresh and review it again.')
        existing=self.connection.execute('SELECT * FROM appeal_privacy_consents WHERE appeal_id=?',(appeal['id'],)).fetchone()
        selected=bool(existing and existing['ai_improvement_opt_in']) if ai_opt_in is None else ai_opt_in
        if selected and not (existing and existing['ai_improvement_opt_in']):
            source=self.source(appeal)
            if not source or not source['automatic'] or not source['message_id'] or not source['content']:
                raise ValueError('Only your own available message moderated automatically is eligible for AI-improvement permission.')
        now=utcnow().isoformat()
        self.connection.execute("""INSERT INTO appeal_privacy_consents
            (appeal_id,server_id,user_id,privacy_version,privacy_accepted_at,ai_improvement_opt_in,ai_notice_version,ai_consented_at,ai_withdrawn_at)
            VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(appeal_id) DO UPDATE SET
            privacy_version=excluded.privacy_version,privacy_accepted_at=excluded.privacy_accepted_at,
            ai_improvement_opt_in=excluded.ai_improvement_opt_in,ai_notice_version=excluded.ai_notice_version,
            ai_consented_at=excluded.ai_consented_at,ai_withdrawn_at=excluded.ai_withdrawn_at""",
            (appeal['id'],appeal['server_id'],appeal['user_id'],privacy_version,now,int(selected),
             AI_NOTICE_VERSION if selected else (existing['ai_notice_version'] if existing else None),
             (existing['ai_consented_at'] if existing and existing['ai_improvement_opt_in'] else now) if selected else (existing['ai_consented_at'] if existing else None),
             None if selected else (now if existing and existing['ai_improvement_opt_in'] else (existing['ai_withdrawn_at'] if existing else None))))
        if not selected:
            self.connection.execute('DELETE FROM appeal_ai_contributions WHERE appeal_id=?',(appeal['id'],))

    def withdraw(self, appeal_id: int) -> None:
        with self.connection:
            self.connection.execute('UPDATE appeal_privacy_consents SET ai_improvement_opt_in=0,ai_withdrawn_at=? WHERE appeal_id=?',(utcnow().isoformat(),appeal_id))
            self.connection.execute('DELETE FROM appeal_ai_contributions WHERE appeal_id=?',(appeal_id,))
        self.checkpoint()

    def checkpoint(self) -> None:
        # secure_delete clears freed SQLite pages; truncate the WAL once readers
        # release it. A busy checkpoint is retried by the periodic sweep.
        if not self.connection.in_transaction:
            self.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()

    @staticmethod
    def scrub(value: Any, texts: set[str]) -> Any:
        if isinstance(value,dict):
            return {key:AppealPrivacyStore.scrub(item,texts) for key,item in value.items() if key not in CONTENT_KEYS}
        if isinstance(value,list):
            return [AppealPrivacyStore.scrub(item,texts) for item in value]
        if isinstance(value,str):
            for text in sorted(texts,key=len,reverse=True):
                if text:value=value.replace(text,'[content deleted]')
        return value

    def purge_case_content(self, appeal: dict[str, Any], *, now: datetime, timed_out: bool = False) -> None:
        source=self.source(appeal)
        consent=self.connection.execute('SELECT * FROM appeal_privacy_consents WHERE appeal_id=?',(appeal['id'],)).fetchone()
        decision_time=parse_time(appeal['reviewed_at']) if appeal.get('reviewed_at') else now
        if source and source['automatic'] and source['message_id'] and source['content'] and consent and consent['ai_improvement_opt_in'] and not timed_out:
            # Bind to the authenticated appellant's stored source, never client-supplied text.
            self.connection.execute("""INSERT OR IGNORE INTO appeal_ai_contributions
                (appeal_id,server_id,user_id,message_id,original_content,created_at,expires_at,notice_version,appeal_outcome)
                VALUES (?,?,?,?,?,?,?,?,?)""",(appeal['id'],appeal['server_id'],appeal['user_id'],source['message_id'],source['content'],decision_time.isoformat(),(decision_time+timedelta(days=AI_CONTRIBUTION_DAYS)).isoformat(),consent['ai_notice_version'],appeal['status']))
        if timed_out:
            self.connection.execute('DELETE FROM appeal_ai_contributions WHERE appeal_id=?',(appeal['id'],))
            self.connection.execute('UPDATE appeal_privacy_consents SET ai_improvement_opt_in=0,ai_withdrawn_at=? WHERE appeal_id=?',(now.isoformat(),appeal['id']))
        texts={str(r[0]) for r in self.connection.execute("SELECT message FROM appeal_messages WHERE appeal_id=? AND sender_type='appellant'",(appeal['id'],)) if r[0]}
        if appeal.get('statement'):texts.add(appeal['statement'])
        if source and source.get('content'):texts.add(source['content'])
        if source and source['message_id']:
            self.purge_message(appeal['server_id'],source['message_id'],now=now,texts=texts)
        elif source:
            case=source['case']
            if case['source_type']=='warning':
                row=self.connection.execute('SELECT reason FROM warnings WHERE id=?',(case['source_id'],)).fetchone()
                self.connection.execute('UPDATE warnings SET original_content=NULL,ai_thinking_json=NULL,reason=? WHERE id=?',(self.scrub(row['reason'],texts),case['source_id']))
            else:
                row=self.connection.execute('SELECT details_json FROM moderation_events WHERE id=?',(case['source_id'],)).fetchone()
                if row:self.connection.execute('UPDATE moderation_events SET details_json=? WHERE id=?',(json.dumps(self.scrub(json.loads(row[0]),texts)),case['source_id']))
        self.purge_case_entries(appeal['server_id'],appeal['case_reference'])
        row=self.connection.execute('SELECT reason FROM moderation_cases WHERE server_id=? AND reference_id=?',(appeal['server_id'],appeal['case_reference'])).fetchone()
        if row:
            self.connection.execute('UPDATE moderation_cases SET reason=? WHERE server_id=? AND reference_id=?',(self.scrub(row['reason'],texts),appeal['server_id'],appeal['case_reference']))
        self.connection.execute('DELETE FROM appeal_message_attachments WHERE message_id IN (SELECT id FROM appeal_messages WHERE appeal_id=?)',(appeal['id'],))
        self.connection.execute('DELETE FROM appeal_messages WHERE appeal_id=?',(appeal['id'],))
        self.connection.execute('UPDATE appeals SET statement=NULL,reviewer_response=? WHERE id=?',(self.scrub(appeal.get('reviewer_response'),texts),appeal['id']))
        self.scrub_actions(appeal['server_id'],texts,appeal_id=appeal['id'],case_reference=appeal['case_reference'])
        self.connection.execute('INSERT OR IGNORE INTO appeal_content_disposals VALUES (?,?,?)',(appeal['id'],now.isoformat(),'timeout' if timed_out else 'decision'))

    def purge_case_entries(self, server_id: str, reference: str) -> None:
        self.connection.execute('DELETE FROM moderation_case_entry_attachments WHERE entry_id IN (SELECT id FROM moderation_case_entries WHERE server_id=? AND case_reference=?)',(server_id,reference))
        self.connection.execute('DELETE FROM moderation_case_entries WHERE server_id=? AND case_reference=?',(server_id,reference))

    def scrub_actions(self, server_id: str, texts: set[str], **identifiers: Any) -> None:
        def matches(value: Any) -> bool:
            if isinstance(value, dict):
                return any(expected is not None and str(value.get(key)) == str(expected) for key, expected in identifiers.items()) or any(matches(child) for child in value.values())
            return isinstance(value, list) and any(matches(child) for child in value)
        for row in self.connection.execute('SELECT id,payload_json,result_json FROM dashboard_actions WHERE server_id=?',(server_id,)).fetchall():
            payload=json.loads(row['payload_json'] or '{}')
            if not matches(payload):continue
            self.connection.execute('UPDATE dashboard_actions SET payload_json=?,result_json=? WHERE id=?',(json.dumps(self.scrub(payload,texts)),json.dumps(self.scrub(json.loads(row['result_json'] or '{}'),texts)),row['id']))

    def purge_message(self, server_id: str, message_id: str, *, now: datetime, texts: set[str] | None = None) -> None:
        texts=set(texts or ())
        warnings=self.connection.execute('SELECT id,original_content,reason FROM warnings WHERE server_id=? AND message_id=?',(server_id,message_id)).fetchall()
        texts.update(r['original_content'] for r in warnings if r['original_content'])
        events=self.connection.execute('SELECT id,details_json FROM moderation_events WHERE server_id=? AND message_id=?',(server_id,message_id)).fetchall()
        for row in events:
            content=json.loads(row['details_json']).get('original_content')
            if isinstance(content,str) and content:texts.add(content)
        for row in warnings:
            self.connection.execute('UPDATE warnings SET original_content=NULL,ai_thinking_json=NULL,reason=? WHERE id=?',(self.scrub(row['reason'],texts),row['id']))
        for row in events:
            self.connection.execute('UPDATE moderation_events SET details_json=? WHERE id=?',(json.dumps(self.scrub(json.loads(row['details_json']),texts)),row['id']))
        for source_type,source_rows in [('warning',warnings),('event',events)]:
            for row in source_rows:
                for case in self.connection.execute('SELECT reference_id,reason FROM moderation_cases WHERE server_id=? AND source_type=? AND source_id=?',(server_id,source_type,row['id'])).fetchall():
                    self.purge_case_entries(server_id,case['reference_id'])
                    self.connection.execute('UPDATE moderation_cases SET reason=? WHERE server_id=? AND reference_id=?',(self.scrub(case['reason'],texts),server_id,case['reference_id']))
                    self.scrub_actions(server_id,texts,case_reference=case['reference_id'])
                if source_type=='warning':self.scrub_actions(server_id,texts,warning_id=row['id'])
        self.scrub_actions(server_id,texts,message_id=message_id)
        self.connection.execute('UPDATE moderated_content_lifecycles SET purged_at=? WHERE server_id=? AND message_id=?',(now.isoformat(),server_id,message_id))

    @staticmethod
    def _has_content(value: Any) -> bool:
        if isinstance(value,dict):
            return any((key in CONTENT_KEYS and item not in (None,'',[],{})) or AppealPrivacyStore._has_content(item) for key,item in value.items())
        return isinstance(value,list) and any(AppealPrivacyStore._has_content(item) for item in value)

    def _expire_attachments(self, *, cutoff: str) -> int:
        """Uploaded files and images (report evidence, support email, case notes incl. flagged-image copies, appeal
        messages) are kept for at most 30 days, unless a submitted appeal still needs its case's files."""
        statements=[
            ('DELETE FROM user_report_attachments WHERE report_id IN (SELECT id FROM user_reports WHERE created_at<=?)',(cutoff,)),
            ('DELETE FROM email_attachments WHERE created_at<=?',(cutoff,)),
            ("""DELETE FROM moderation_case_entry_attachments WHERE created_at<=? AND entry_id NOT IN (
                SELECT entry.id FROM moderation_case_entries AS entry JOIN appeals AS appeal
                  ON appeal.server_id=entry.server_id AND appeal.case_reference=entry.case_reference
                WHERE appeal.status='submitted')""",(cutoff,)),
            ("""DELETE FROM appeal_message_attachments WHERE created_at<=? AND message_id NOT IN (
                SELECT message.id FROM appeal_messages AS message JOIN appeals AS appeal ON appeal.id=message.appeal_id
                WHERE appeal.status='submitted')""",(cutoff,)),
        ]
        return sum(self.connection.execute(sql,params).rowcount for sql,params in statements)

    def _open_appeal_messages(self) -> set[tuple[str,str]]:
        protected: set[tuple[str,str]]=set()
        for appeal in self.connection.execute("SELECT * FROM appeals WHERE case_kind='moderation' AND server_id IS NOT NULL AND status='submitted'").fetchall():
            source=self.source(dict(appeal))
            if source and source['message_id']:protected.add((appeal['server_id'],source['message_id']))
        return protected

    def _expire_event_content(self, *, now: datetime, cutoff: str) -> int:
        """Message content kept in ANY moderation event (rule-based link deletions, self-harm deletions, automations, ...) follows the same
        30-day limit as AI-moderated content, unless an open appeal still needs the message. Throttled to once per ten minutes."""
        last=getattr(self,'_event_sweep_at',None)
        if last is not None and last<=now<last+timedelta(minutes=10):
            return 0
        self._event_sweep_at=now
        protected=self._open_appeal_messages()
        like=' OR '.join("details_json LIKE ?" for _ in CONTENT_KEYS)
        rows=self.connection.execute(f"SELECT id,server_id,message_id,details_json FROM moderation_events WHERE created_at<=? AND ({like})",(cutoff,*[f'%"{key}"%' for key in sorted(CONTENT_KEYS)])).fetchall()
        expired=0; purged: set[tuple[str,str]]=set()
        for row in rows:
            try:details=json.loads(row['details_json'])
            except (TypeError,ValueError):continue
            if not isinstance(details,dict) or not self._has_content(details):continue
            key=(row['server_id'],row['message_id']) if row['message_id'] else None
            if key in protected:continue
            texts={value for value in (details.get('original_content'),details.get('original_message'),details.get('message_content'),details.get('content')) if isinstance(value,str) and value}
            if key is not None:
                if key not in purged:
                    self.purge_message(row['server_id'],row['message_id'],now=now,texts=texts)
                    purged.add(key)
            else:
                self.connection.execute('UPDATE moderation_events SET details_json=? WHERE id=?',(json.dumps(self.scrub(details,texts)),row['id']))
            expired+=1
        return expired

    def prune(self, *, now: datetime | None = None) -> dict[str,int]:
        if not self.connection.in_transaction:
            self.connection.execute('BEGIN IMMEDIATE')
        now=now or utcnow(); result={'expired_messages':0,'timed_out_appeals':0,'expired_contributions':0,'expired_event_content':0}
        cutoff=(now-timedelta(days=APPEAL_DAYS)).isoformat()
        timed_out=self.connection.execute("SELECT * FROM appeals WHERE case_kind='moderation' AND server_id IS NOT NULL AND status='submitted' AND submitted_at<=?",(cutoff,)).fetchall()
        for row in timed_out:
            appeal=dict(row)
            updated=self.connection.execute("UPDATE appeals SET status='denied',reviewed_at=?,reviewer_id='STOATMOD_APPEAL_TIMEOUT',reviewer_response=? WHERE id=? AND status='submitted'",(now.isoformat(),'Automatically rejected: no decision was made within 10 days. Submitted content has been deleted.',row['id']))
            if not updated.rowcount:continue
            appeal.update(status='denied',reviewer_response='Automatically rejected: no decision was made within 10 days. Submitted content has been deleted.')
            self.purge_case_content(appeal,now=now,timed_out=True)
            # Queue the DM and server log independently, in the same transaction
            # as the decision and deletion. Neither needs a copy of the content.
            self.connection.execute("INSERT INTO dashboard_actions(server_id,action,actor_id,payload_json,created_at) VALUES (?,'resolve_appeal','STOATMOD_APPEAL_TIMEOUT',?,?)",(row['server_id'],json.dumps({'appeal_id':row['id'],'decision':'denied','automatic_log_queued':True}),now.isoformat()))
            self.connection.execute("INSERT INTO dashboard_actions(server_id,action,actor_id,payload_json,created_at) VALUES (?,'log_automatic_appeal_decision','STOATMOD_APPEAL_TIMEOUT',?,?)",(row['server_id'],json.dumps({'appeal_id':row['id']}),now.isoformat()))
            result['timed_out_appeals']+=1
        for row in self.connection.execute("SELECT * FROM appeals WHERE case_kind='moderation' AND server_id IS NOT NULL AND status IN ('approved','denied') AND id NOT IN (SELECT appeal_id FROM appeal_content_disposals)").fetchall():
            self.purge_case_content(dict(row),now=now,timed_out=row['reviewer_id']=='STOATMOD_APPEAL_TIMEOUT')
        cutoff=(now-timedelta(days=CONTENT_DAYS)).isoformat()
        for row in self.connection.execute('SELECT * FROM moderated_content_lifecycles WHERE purged_at IS NULL AND decided_at<=?',(cutoff,)).fetchall():
            protected=False
            for appeal in self.connection.execute("SELECT * FROM appeals WHERE server_id=? AND user_id=? AND status='submitted'",(row['server_id'],row['user_id'])).fetchall():
                source=self.source(dict(appeal))
                if source and source['message_id']==row['message_id']:protected=True;break
            if not protected:
                self.purge_message(row['server_id'],row['message_id'],now=now)
                result['expired_messages']+=1
        result['expired_event_content']=self._expire_event_content(now=now,cutoff=cutoff)
        result['expired_attachments']=self._expire_attachments(cutoff=cutoff)
        result['expired_contributions']=self.connection.execute('DELETE FROM appeal_ai_contributions WHERE expires_at<=?',(now.isoformat(),)).rowcount
        self.connection.commit()
        self.checkpoint()
        return result
