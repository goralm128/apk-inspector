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
    def __init__(self, hooks_dir: Path, logger, rule_engine: RuleEngine, tag_inferencer: TagInferencer, timeout=60, grace_period=5):
        self.hooks_dir = hooks_dir
        self.logger = logger
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
                self.logger.warning(f"[!] Failed to load metadata from {path.name}: {ex}")
        return metadata_map

    def _process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        # Enforce dict
        if not isinstance(event, dict):
            try:
                event = event.model_dump()  # or asdict(event)
            except Exception:
                self.logger.warning("[!] Non-dict event; skipping")
                return {}

        # Ensure event_id
        event.setdefault("event_id", str(uuid4()))
        event["source_hook"] = event.get("hook", "unknown")

        meta = self.hook_metadata_map.get(event["source_hook"], {})
        event["category"] = meta.get("category", "uncategorized")
        if event["category"] == "uncategorized":
            self.logger.warning(f"[!] Uncategorized hook: {event['source_hook']}")

        # Tag inference
        tags = event.get("tags", [])
        inferred = self.tag_inferencer.infer_tags(event)
        event["tags"] = list(set(tags + inferred))

        # Path classification
        fp = extract_file_path(event)
        if fp:
            event["path_type"] = classify_path(fp)

        # Score/event-level
        score, label, justification = self.rule_engine._score_event(event)
        event.update({"score": score, "label": label, "justification": justification})

        self.logger.debug(f"[EVENT] {event['event_id']} after processing: {json.dumps(event, indent=2)}")
        return event

    def analyze(self, package_name: str) -> Dict[str, Any]:
        self.logger.info(f"[{package_name}] Starting dynamic analysis")
        try:
            session = FridaSessionManager(package_name, self.hooks_dir, self.helpers_path, self.logger, self.timeout, self.grace_period)
            self.logger.info(f"[{package_name}] FridaSessionManager created")
            result = session.run()
            if isinstance(result, dict):
                keys = list(result.keys())
                summary = f"dict with keys: {keys}"
            elif isinstance(result, list):
                summary = f"list with {len(result)} item(s)"
            else:
                summary = f"type: {type(result).__name__}"

            self.logger.info(f"[{package_name}] FridaSessionManager session - run launched, result summary: {summary}")

            raw_events = result["events"] if isinstance(result, dict) and "events" in result else result if isinstance(result, list) else []
            self.logger.info(f"[{package_name}] Raw events: {json.dumps(raw_events, indent=2)[:500]}")
        
            processed = []
            for raw_evt in raw_events:
                evt = self._process_event(raw_evt)
                if evt:
                    processed.append(evt)
            self.logger.info(f"[{package_name}] Processed {len(processed)}/{len(raw_events)} events")

            filtered = [
                event for event in processed
                if not (event.get("address", {}).get("ip") and is_private_ip(event["address"]["ip"]))
            ]

            self.logger.info(f"[{package_name}] Filtered local IP events => {len(filtered)} remain")

            deduped = deduplicate_events(filtered)
            self.logger.info(f"[{package_name}] Deduplicated events => {len(deduped)} final")

            self.hook_coverage = Counter(e.get("hook", "unknown") for e in deduped)
            for evt in deduped[:15]:
                self.logger.info(f"[EVENT] {evt['event_id']}: {json.dumps(evt, indent=2)}")
            self.logger.info(f"[{package_name}] Hook coverage: {dict(self.hook_coverage)}")

            return {"events": deduped, "hook_coverage": dict(self.hook_coverage)}

        except Exception as ex:
            self.logger.exception(f"[{package_name}] Dynamic analysis failed: {ex}")
            return {"events": [], "hook_coverage": {}}

        finally:
            if is_device_connected():
                self.logger.info(f"[{package_name}] Stopping app")
                force_stop_app(package_name)
