"""trajectory.py — the data substrate for the owned-model arc.

A Trajectory captures one full agent run as a structured record: the system prompt, the
objective, the scope, and every turn (the model's content blocks + the tool results we
fed back), plus the outcome. Saved as JSONL (one run per line) this is the raw material
for distillation: the strong brain (Claude) is the teacher, and these recordings become
supervised examples for a local student model.

Nothing here is heuristic or invented — it is a faithful transcript of what actually
happened, so the dataset can't drift from reality.
"""

from __future__ import annotations

import datetime
import json
import os


class Trajectory:
    def __init__(self, objective: str, scope_entries, system: str = "",
                 model: str = ""):
        self.objective = objective
        self.scope = list(scope_entries)
        self.system = system
        self.model = model
        self.started = datetime.datetime.now().isoformat(timespec="seconds")
        self.turns: list[dict] = []
        self.outcome: dict = {}

    def add_turn(self, assistant_content, tool_results) -> None:
        """Record one loop iteration: the model's blocks and the tool results returned."""
        self.turns.append({
            "assistant": assistant_content,
            "tool_results": tool_results,
        })

    def finish(self, final_text: str, stop_reason: str, findings_count: int = 0) -> None:
        self.outcome = {
            "final_text": final_text,
            "stop_reason": stop_reason,
            "findings_count": findings_count,
            "turns": len(self.turns),
        }

    # ---- serialization ---------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "started": self.started,
            "model": self.model,
            "objective": self.objective,
            "scope": self.scope,
            "system": self.system,
            "turns": self.turns,
            "outcome": self.outcome,
        }

    def save(self, path: str) -> None:
        """Append this run as one JSON line to a JSONL dataset file."""
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(self.to_dict(), default=str, ensure_ascii=False) + "\n")

    # ---- training view ---------------------------------------------------

    def sft_messages(self) -> list:
        """Reconstruct the conversation in Messages-API format.

        This is the imitation/distillation sample: given the same system + objective +
        tool feedback, the student should learn to produce the teacher's assistant turns.
        """
        messages = [{"role": "user", "content": self.objective}]
        for turn in self.turns:
            messages.append({"role": "assistant", "content": turn["assistant"]})
            if turn["tool_results"]:
                messages.append({"role": "user", "content": turn["tool_results"]})
        return messages


def load_jsonl(path: str) -> list:
    """Load a JSONL trajectory dataset back into a list of dicts."""
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
