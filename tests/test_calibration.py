"""S5: веса скоринга калибруются по НАБЛЮДАЕМЫМ отскокам, а не по мнению.

Ключевой тест здесь — test_weight_follows_observed_bounce_rate: он строит
данные, где сигнал заведомо связан с отскоками, и требует, чтобы вес пошёл
в ту же сторону. Если калибровка начнёт возвращать константу, он покраснеет.
"""

import csv
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import scoring
from tools import calibrate_scoring as cal


def write_csv(path, rows, fields):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def make_dataset(tmp, n_with, n_without, bounce_with, bounce_without,
                 signal_text="+10: Есть Gravatar (реальный человек)"):
    """Строит выгрузку и bounce-лог с ЗАДАННОЙ связью сигнала и отскоков."""
    results, bounced = [], []
    for i in range(n_with):
        email = f"with{i}@x.com"
        results.append({"Email": email, "Signals": signal_text})
        bounced.append({"email": email,
                        "bounced": "1" if i < int(n_with * bounce_with) else "0"})
    for i in range(n_without):
        email = f"without{i}@x.com"
        results.append({"Email": email, "Signals": "+2: Базовый DNS (1 из 3)"})
        bounced.append({"email": email,
                        "bounced": "1" if i < int(n_without * bounce_without) else "0"})

    res_path = os.path.join(tmp, "results.csv")
    bnc_path = os.path.join(tmp, "bounces.csv")
    write_csv(res_path, results, ["Email", "Signals"])
    write_csv(bnc_path, bounced, ["email", "bounced"])
    return res_path, bnc_path


class TestCalibrationMeasures(unittest.TestCase):

    def test_weight_follows_observed_bounce_rate(self):
        """Сигнал, который РЕАЛЬНО снижает отскоки, обязан получить плюс."""
        with tempfile.TemporaryDirectory() as tmp:
            # С сигналом отскакивает 5%, без него — 45%. Сигнал сильный и добрый.
            res, bnc = make_dataset(tmp, 200, 200, 0.05, 0.45)
            bounced, mailed = cal.read_bounces(bnc)
            weights, _report = cal.calibrate(cal.read_results(res), bounced, mailed)
            self.assertIn("gravatar", weights)
            self.assertGreater(weights["gravatar"], 0,
                               "сигнал снижает отскоки, а вес получился неположительным")
            self.assertAlmostEqual(weights["gravatar"], 40, delta=3,
                                   msg="вес не соответствует измеренной разнице долей")

    def test_weight_flips_sign_when_signal_predicts_bounces(self):
        """Тот же сигнал с противоположной статистикой обязан дать минус."""
        with tempfile.TemporaryDirectory() as tmp:
            # Теперь наоборот: с сигналом отскакивает 60%, без него — 10%
            res, bnc = make_dataset(tmp, 200, 200, 0.60, 0.10)
            bounced, mailed = cal.read_bounces(bnc)
            weights, _ = cal.calibrate(cal.read_results(res), bounced, mailed)
            self.assertLess(weights["gravatar"], 0,
                            "сигнал предсказывает отскоки, а вес остался положительным")

    def test_small_sample_leaves_weight_untouched(self):
        """На двадцати адресах «измерение» — это шум. Трогать вес нельзя."""
        with tempfile.TemporaryDirectory() as tmp:
            res, bnc = make_dataset(tmp, 10, 10, 0.0, 1.0)
            bounced, mailed = cal.read_bounces(bnc)
            weights, report = cal.calibrate(cal.read_results(res), bounced, mailed)
            self.assertNotIn("gravatar", weights,
                             "вес подменён по выборке меньше порога")
            skipped = [r for r in report if r["signal"] == "gravatar"]
            self.assertTrue(skipped and "мало" in skipped[0].get("reason", ""))

    def test_smtp_verdict_is_never_recalibrated(self):
        """Вердикт SMTP — доказательство, а не статистический признак."""
        with tempfile.TemporaryDirectory() as tmp:
            res, bnc = make_dataset(tmp, 200, 200, 0.05, 0.45)
            bounced, mailed = cal.read_bounces(bnc)
            weights, _ = cal.calibrate(cal.read_results(res), bounced, mailed)
            for frozen in cal.FROZEN:
                self.assertNotIn(frozen, weights,
                                 f"{frozen} перекалиброван по одной рассылке")

    def test_weight_is_clamped_to_scale(self):
        with tempfile.TemporaryDirectory() as tmp:
            res, bnc = make_dataset(tmp, 200, 200, 0.0, 1.0)
            bounced, mailed = cal.read_bounces(bnc)
            weights, _ = cal.calibrate(cal.read_results(res), bounced, mailed)
            self.assertLessEqual(abs(weights["gravatar"]), cal.MAX_WEIGHT)

    def test_cli_refuses_empty_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = os.path.join(tmp, "r.csv")
            bnc = os.path.join(tmp, "b.csv")
            write_csv(res, [], ["Email", "Signals"])
            write_csv(bnc, [], ["email", "bounced"])
            code = cal.main(["--results", res, "--bounces", bnc])
            self.assertEqual(code, 1, "калибровка согласилась работать на пустых данных")

    def test_cli_writes_weights_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            res, bnc = make_dataset(tmp, 200, 200, 0.05, 0.45)
            out = os.path.join(tmp, "weights.json")
            code = cal.main(["--results", res, "--bounces", bnc, "-o", out])
            self.assertEqual(code, 0)
            data = json.load(open(out, encoding="utf-8"))
            self.assertIn("gravatar", data["weights"])

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            res, bnc = make_dataset(tmp, 200, 200, 0.05, 0.45)
            out = os.path.join(tmp, "weights.json")
            code = cal.main(["--results", res, "--bounces", bnc, "-o", out, "--dry-run"])
            self.assertEqual(code, 0)
            self.assertFalse(os.path.exists(out), "--dry-run записал файл")


class TestScoringUsesWeights(unittest.TestCase):
    """Калибровка бессмысленна, если скоринг её не читает."""

    def tearDown(self):
        scoring.reset_weights()

    def test_scoring_reads_calibrated_weights_from_disk(self):
        base = scoring.calculate_engagement_score("a@gmail.com", "Valid", "250 OK",
                                                  has_gravatar=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "w.json")
            json.dump({"weights": {"gravatar": 30}}, open(path, "w", encoding="utf-8"))
            replaced = scoring.load_weights(path)
            self.assertEqual(replaced, 1)
            tuned = scoring.calculate_engagement_score("a@gmail.com", "Valid", "250 OK",
                                                       has_gravatar=True)
        self.assertEqual(tuned["score"] - base["score"], 20,
                         "скоринг не подхватил откалиброванный вес")

    def test_broken_weights_file_is_ignored(self):
        """Испорченный файл не должен молча сломать шкалу."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "w.json")
            open(path, "w", encoding="utf-8").write("{не json")
            self.assertEqual(scoring.load_weights(path), 0)
            self.assertEqual(scoring.get_weights(), scoring.DEFAULT_WEIGHTS)

    def test_out_of_range_weight_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "w.json")
            json.dump({"weights": {"gravatar": 10000, "in_dnsbl": -35}},
                      open(path, "w", encoding="utf-8"))
            scoring.load_weights(path)
            self.assertEqual(scoring.get_weights()["gravatar"],
                             scoring.DEFAULT_WEIGHTS["gravatar"],
                             "вес вне диапазона принят и сломал шкалу")
            self.assertEqual(scoring.get_weights()["in_dnsbl"], -35,
                             "разумный вес из того же файла отброшен вместе с плохим")

    def test_unknown_key_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "w.json")
            json.dump({"weights": {"нет_такого_сигнала": 50}},
                      open(path, "w", encoding="utf-8"))
            self.assertEqual(scoring.load_weights(path), 0)

    def test_missing_file_is_not_an_error(self):
        """Файла нет — работаем на значениях по умолчанию, как раньше."""
        self.assertEqual(scoring.load_weights("нет-такого-файла.json"), 0)
        self.assertEqual(scoring.get_weights(), scoring.DEFAULT_WEIGHTS)


if __name__ == "__main__":
    unittest.main()
