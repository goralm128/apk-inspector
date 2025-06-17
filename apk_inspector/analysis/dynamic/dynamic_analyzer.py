from pathlib import Path
from typing import Dict, Any, List
from apk_inspector.analysis.dynamic.frida_session_mngr import FridaSessionManager
from apk_inspector.utils.file_utils import deduplicate_events, is_private_ip
from apk_inspector.utils.fs_utils import extract_file_path
from apk_inspector.analysis.data_classifier import classify_path
from tools.adb_tools import is_device_connected, force_stop_app
from apk_inspector.rules.rule_engine import RuleEngine
from apk_inspector.analysis.tag_inferencer import TagInferencer
from apk_inspector.analysis.dynamic.hook_descovery import extract_metadata_from_hook
import json
from collections import Counter
from uuid import uuid4

class DynamicAnalyzer:
    def __init__(
        self,
        hooks_dir: Path,
        logger,
        rule_engine: RuleEngine,
        tag_inferencer: TagInferencer,
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
        self.hook_coverage: Dict[str, int] = {}

    def _load_hook_metadata(self) -> Dict[str, Any]:
        metadata_map = {}
        for path in self.hooks_dir.glob("hook_*.js"):
            try:
                metadata = extract_metadata_from_hook(path)
                if metadata and metadata.get("name"):
                    metadata_map[metadata["name"]] = metadata
            except Exception as ex:
                self.logger.warning(f"[HOOK METADATA] Failed to load from {path.name}: {ex}")
        return metadata_map

    def _process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(event, dict):
            try:
                event = event.model_dump()
            except Exception:
                self.logger.warning("[EVENT] Invalid format; skipped")
                return {}

        event.setdefault("event_id", str(uuid4()))
        event["source_hook"] = event.get("hook", "unknown")

        meta = self.hook_metadata_map.get(event["source_hook"], {})
        event["category"] = meta.get("category", "uncategorized")
        if event["category"] == "uncategorized":
            self.logger.warning(f"[HOOK] Uncategorized: {event['source_hook']}")

        event["tags"] = list(set(event.get("tags", []) + self.tag_inferencer.infer_tags(event)))

        if (fp := extract_file_path(event)):
            event["path_type"] = classify_path(fp)

        score, label, justification = self.rule_engine._score_event(event)
        event.update({"score": score, "label": label, "justification": justification})

        self.logger.debug(f"[EVENT] {event['event_id']}:\n{json.dumps(event, indent=2)}")
        return event

    def analyze(self, package_name: str) -> Dict[str, Any]:
        self.logger.info(f"[{package_name}] ▶ Starting dynamic analysis...")

        try:
            session_mgr = FridaSessionManager(
                package_name=package_name,
                hooks_dir=self.hooks_dir,
                helpers_path=self.helpers_path,
                run_dir=self.run_dir,
                logger=self.logger,
                timeout=90,
                grace_period=self.grace_period
            )
            self.logger.info(f"[{package_name}] Session manager initialized.")

            result = session_mgr.run()
            raw_events = result.get("events", []) if isinstance(result, dict) else []

            self.logger.info(f"[{package_name}] Raw events count: {len(raw_events)}")
            processed = [self._process_event(e) for e in raw_events if e]
            self.logger.info(f"[{package_name}] Processed events: {len(processed)}")

            filtered = [
                evt for evt in processed
                if not (evt.get("address", {}).get("ip") and is_private_ip(evt["address"]["ip"]))
            ]
            self.logger.info(f"[{package_name}] After filtering private IPs: {len(filtered)}")

            deduped = deduplicate_events(filtered)
            self.logger.info(f"[{package_name}] Deduplicated events: {len(deduped)}")

            self.hook_coverage = Counter(e.get("hook", "unknown") for e in deduped)
            for evt in deduped[:15]:
                self.logger.info(f"[EVENT] {evt['event_id']}:\n{json.dumps(evt, indent=2)}")
            self.logger.info(f"[{package_name}] Hook coverage: {dict(self.hook_coverage)}")

            return {
                "events": deduped,
                "hook_coverage": dict(self.hook_coverage)
            }

        except Exception as ex:
            self.logger.exception(f"[{package_name}] ❌ Dynamic analysis failed: {ex}")
            return {"events": [], "hook_coverage": {}}

        finally:
            if is_device_connected():
                self.logger.info(f"[{package_name}] ⏹ Stopping app...")
                force_stop_app(package_name)