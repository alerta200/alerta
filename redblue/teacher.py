"""teacher.py — capture GOLD trajectories from a strong brain (the distillation teacher).

The owned-model arc needs training data: examples of an expert doing the pentest well.
The strongest brain available here is Claude (the assistant driving this session) — at no
API cost. This module lets that teacher drive redblue's real tools step by step and record
the run in the exact same Trajectory format the autonomous agent produces, so the resulting
samples are drop-in supervised data for fine-tuning a local student (Qwen on cppinfer).

Every tool call is run for real and scope-gated — the tool_results are genuine, not invented.
The teacher authors only the reasoning and the final report.
"""

from __future__ import annotations

from .scope import Scope
from .trajectory import Trajectory
from .agent import SYSTEM_PROMPT
from . import tools


class Teacher:
    def __init__(self, scope: Scope, objective: str, target: str = "",
                 model: str = "claude-teacher"):
        self.scope = scope
        self.objective = objective
        self.traj = Trajectory(objective, scope.raw)
        self.traj.system = SYSTEM_PROMPT.format(
            scope=", ".join(scope.raw) or "(empty!)",
            target=target or (scope.raw[0] if scope.raw else "(unset)"))
        self.traj.model = model
        self._n = 0

    def step(self, reasoning: str, tool_name: str, tool_input: dict) -> dict:
        """Author one reasoned tool call; run it for real; record the turn.

        Returns the parsed/captured tool result so the teacher can decide the next move.
        """
        self._n += 1
        tid = f"t{self._n}"
        out, is_error = tools.dispatch(tool_name, tool_input, self.scope)
        assistant = [
            {"type": "text", "text": reasoning},
            {"type": "tool_use", "id": tid, "name": tool_name, "input": tool_input},
        ]
        tool_results = [{
            "type": "tool_result", "tool_use_id": tid,
            "content": out, "is_error": is_error,
        }]
        self.traj.add_turn(assistant, tool_results)
        return {"content": out, "is_error": is_error}

    def finish(self, report: str) -> Trajectory:
        """Author the final report turn and close the trajectory."""
        self.traj.add_turn([{"type": "text", "text": report}], [])
        self.traj.finish(report, "end_turn")
        return self.traj
