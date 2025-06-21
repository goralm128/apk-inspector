from pathlib import Path
from typing import Dict, Any, List
from collections import Counter
from uuid import uuid4
import json

from apk_inspector.analysis.dynamic.frida_session_mngr import FridaSessionManager
from apk_inspector.utils.file_utils import deduplicate_events, is_private_ip
from apk_inspector.utils.fs_utils import extract_file_path
from apk_inspector.analysis.data_classifier import classify_path
from tools.adb_tools import is_device_connected, force_stop_app
from apk_inspector.rules.rule_engine import RuleEngine
from apk_inspector.analysis.tag_inferencer import TagInferencer
from apk_inspector.analysis.dynamic.hook_descovery import extract_metadata_from_hook


class DynamicAnalyzer:
    def __init__(
        self,
        hooks_dir: Path,
        logger,
        rule_engine,
        tag_inferencer,
        run_dir: Path,
        timeout: int = 60,
        grace_period: int = 5
    ):
        self.hooks_dir = hooks_dir
        self.logger = logger
        self.run_dir = run_dir
        self.timeout = timeout
        self.grace_period = grace_period
        self.helpers_path = Path("frida/helpers/frida_helpers.js")
        self.rule_engine = rule_engine
        self.tag_inferencer = tag_inferencer
        self.hook_metadata_map = self._load_hook_metadata()
        self.hook_event_counts: Dict[str, int] = {}     

    def _load_hook_metadata(self) -> Dict[str, Dict[str, Any]]:
        metadata_map = {}
        for path in self.hooks_dir.glob("hook_*.js"):
            try:
                metadata = extract_metadata_from_hook(path)
                if metadata and metadata.get("name"):
                    metadata_map[metadata["name"]] = metadata
            except Exception as ex:
                self.logger.warning(f"[HOOK METADATA] ❌ Failed to load from {path.name}: {ex}")
        return metadata_map

    def _process_event(self, event: Dict[str, Any], apk_metadata=None) -> Dict[str, Any]:
        if not isinstance(event, dict):
            self.logger.warning("[EVENT] ❌ Invalid event format (non-dict)")
            return {}

        # ─── Enrich with APK metadata ──────────────────────────────
        if apk_metadata:
            event.setdefault("apk", {}).update({
                "package_name": apk_metadata.get("package_name"),
                "apk_name": apk_metadata.get("apk_name"),
                "sha256": apk_metadata.get("sha256")
            })

        # ─── Normalize fields ──────────────────────────────────────
        event.setdefault("event_id", str(uuid4()))
        event["source_hook"] = event.get("hook", "unknown")
        meta = self.hook_metadata_map.get(event["source_hook"], {})
        event.setdefault("category", meta.get("category", "uncategorized"))

        # ─── Tagging system ────────────────────────────────────────
        tags = set(event.get("tags", []))
        tags.update(meta.get("tags", []))
        tags.update(self.tag_inferencer.infer_tags(event))
        event["tags"] = list(tags)

        # ─── File path classifier ──────────────────────────────────
        try:
            file_path = extract_file_path(event)
            if file_path:
                event["path_type"] = classify_path(file_path)
        except Exception as e:
            self.logger.debug(f"[EVENT] ⚠ Path classification failed ({event.get('event_id')}): {e}")

        # ─── Scoring and Rule Labeling ─────────────────────────────
        try:
            score, label, justification = self.rule_engine.score_event(event)
            event.update({
                "score": score,
                "label": label,
                "justification": justification
            })
        except Exception as e:
            self.logger.error(f"[RULE ENGINE] ❌ Scoring failed: {e}")

        self.logger.debug(f"[EVENT] Processed: {event['event_id']}\n{json.dumps(event, indent=2)}")
        return event

    def analyze(self, package_name: str, apk_metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        self.logger.info(f"[{package_name}] ▶ Starting dynamic analysis...")

        try:
            session_mgr = FridaSessionManager(
                package_name=package_name,
                hooks_dir=self.hooks_dir,
                helpers_path=self.helpers_path,
                run_dir=self.run_dir,
                logger=self.logger,
                timeout=self.timeout,
                grace_period=self.grace_period
            )

            result = session_mgr.run()

            raw_events = result.get("events", []) if isinstance(result, dict) else []
            java_vm_ready = result.get("java_vm_ready", True)
            jvm_absence_reason = result.get("jvm_absence_reason", "unknown")

            if not java_vm_ready:
                self.logger.warning(f"[{package_name}] ⚠ JVM not available: {jvm_absence_reason}")
                skipped_java = [name for name, meta in self.hook_metadata_map.items() if meta.get("entrypoint") == "java"]
                self.logger.warning(f"[{package_name}] Java hooks skipped: {skipped_java}")

            self.logger.info(f"[{package_name}] Raw events collected: {len(raw_events)}")
            if len(raw_events) == 0:
                self.logger.warning(f"[{package_name}] ❗ Collected 0 events. Check instrumentation or Frida logs.")

            # ─── Dump early diagnostics ──────────────────────────────
            self.logger.debug(f"[{package_name}] Raw event sample:\n{json.dumps(raw_events[:5], indent=2)}")

            # ─── Process and enrich events ───────────────────────────
            processed_events = [self._process_event(e, apk_metadata) for e in raw_events if e]
            self.logger.info(f"[{package_name}] ✅ Processed events: {len(processed_events)}")

            # ─── Filter out private IP traffic ───────────────────────
            filtered = [
                e for e in processed_events
                if not (e.get("address", {}).get("ip") and is_private_ip(e["address"]["ip"]))
            ]
            removed = len(processed_events) - len(filtered)
            if removed:
                self.logger.info(f"[{package_name}] Removed {removed} private IP events")

            # ─── Deduplication phase ────────────────────────────────
            deduped = deduplicate_events(filtered)
            self.logger.info(f"[{package_name}] 📊 Final event count: {len(deduped)}")

            if not deduped:
                self.logger.warning(f"[{package_name}] ⚠ No meaningful dynamic events after filtering.")

            # ─── Stats for hook coverage ─────────────────────────────
            self.hook_event_counts.clear()
            for e in deduped:
                hook = e.get("source_hook") or e.get("hook", "unknown")
                self.hook_event_counts[hook] = self.hook_event_counts.get(hook, 0) + 1

            self.logger.info(f"[{package_name}] 📈 Hook event counts:\n{json.dumps(self.hook_event_counts, indent=2)}")

            return {
                "events": deduped,
                "hook_event_counts": dict(self.hook_event_counts),
                "java_vm_ready": java_vm_ready,
                "jvm_absence_reason": jvm_absence_reason
            }

        except Exception as ex:
            self.logger.exception(f"[{package_name}] ❌ Analysis failure: {ex}")
            return {
                "events": [],
                "hook_event_counts": {},
                "java_vm_ready": False,
                "jvm_absence_reason": "exception"
            }

        finally:
            if is_device_connected():
                self.logger.info(f"[{package_name}] ⏹ Stopping app...")
                force_stop_app(package_name)