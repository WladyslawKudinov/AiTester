"""Многоходовой планировщик диалога — ОПЦИОНАЛЬНО (включается флагом, дефолт single-shot).

Цикл в духе GOAT/Crescendo: ОДИН session_id на весь диалог (стенд копит контекст по session_id),
атакующий выбирает следующий ход по последнему ответу цели, ранний стоп по НАШЕМУ оракулу,
backtracking по отказу. Не заменяет single-shot+adaptive — это отдельный режим для сравнения.

Оракул остаётся рефери: успех определяет target_check (для BAC — отпечатки жертвы в ответе; для
отравления — приземление после finalize через on_turn/финальную проверку в вызывающем таске).
"""

from .isolation import new_session_id


class Conversation:
    def __init__(self, client, attacker, cfg):
        self.client = client
        self.attacker = attacker
        self.cfg = cfg

    def run(self, goal, actor_key, target_check, *, profile=None, max_turns=5,
            max_backtracks=2, auth_mode="vulnerable", strategies=None, model=None):
        """Провести диалог до успеха/лимита. target_check(reply, ctx) -> truthy при успехе.

        Возвращает {success, turns, backtracks, session_id, transcript, hit}.
        transcript — список ходов [{turn, attacker, reply, strategy, status, backtracked?}].
        """
        sid = new_session_id("conv")
        strategies = strategies if strategies is not None else self.cfg.strategies()
        transcript = []
        last_reply = None
        turns_done = 0
        backtracks = 0

        while turns_done < max_turns:
            strat = strategies[min(turns_done, len(strategies) - 1)] if strategies else None
            msg = self.attacker.next_turn(goal, transcript, last_reply, profile, strat, model=model)
            res = self.client.chat(actor_key, msg, session_id=sid, auth_mode=auth_mode)
            reply = res.get("content", "")
            entry = {"turn": turns_done + 1, "attacker": msg, "reply": reply,
                     "strategy": strat, "status": res.get("status")}

            # отказ -> backtrack: перезаходим другой формулировкой, ход НЕ засчитываем
            if self.attacker.is_refusal(reply) and backtracks < max_backtracks:
                backtracks += 1
                entry["backtracked"] = True
                transcript.append(entry)
                last_reply = reply          # next_turn увидит отказ и переформулирует
                continue

            turns_done += 1
            transcript.append(entry)
            last_reply = reply
            hit = target_check(reply, {"session_id": sid, "turn": turns_done, "transcript": transcript})
            if hit:
                return {"success": True, "turns": turns_done, "backtracks": backtracks,
                        "session_id": sid, "transcript": transcript, "hit": hit}

        return {"success": False, "turns": turns_done, "backtracks": backtracks,
                "session_id": sid, "transcript": transcript, "hit": None}
