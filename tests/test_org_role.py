import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.org_role import (JOB_ROLES, company_from_domain, enrich_org_role,
                           role_from_local_part)


class TestCompanyFromDomain(unittest.TestCase):
    def test_corporate_domain_gives_the_company(self):
        cases = {
            ("veltrano.com", "Corporate"): "Veltrano",
            ("mira-velko.com", "Corporate"): "Mira Velko",
            ("astirit.com", "Corporate"): "Astirit",
            ("acme-corp.io", "Corporate"): "Acme Corp",
            ("bbc.co.uk", "Corporate"): "Bbc",
            ("example.com.au", "Corporate"): "Example",
            ("mail.startup.io", "Corporate"): "Startup",
        }
        for (domain, kind), expected in cases.items():
            with self.subTest(domain=domain):
                self.assertEqual(company_from_domain(domain, kind), expected)

    def test_free_provider_has_no_company(self):
        for domain in ("gmail.com", "yahoo.com", "outlook.com", "mail.ru",
                       "yandex.ru", "gmx.de", "qq.com"):
            with self.subTest(domain=domain):
                self.assertEqual(company_from_domain(domain, "Personal"), "",
                                 "бесплатный почтовик выдан за работодателя")

    def test_isp_is_not_a_company_either(self):
        self.assertEqual(company_from_domain("comcast.net", "ISP"), "")

    def test_garbage_gives_empty(self):
        for junk in (None, "", "   ", "com", ".", "..", 0, [], {}, b"x.com"):
            with self.subTest(junk=junk):
                self.assertEqual(company_from_domain(junk, "Corporate"), "")


class TestRoleFromLocalPart(unittest.TestCase):
    def test_plain_roles(self):
        cases = {
            "sales": "Продажи", "hr": "Кадры", "ceo": "Генеральный директор",
            "support": "Поддержка", "info": "Общий контакт",
            "billing": "Биллинг", "legal": "Юридический отдел",
            "webmaster": "Веб-мастер", "cto": "Технический директор",
        }
        for local, expected in cases.items():
            with self.subTest(local=local):
                self.assertEqual(role_from_local_part(local), expected)

    def test_roles_with_digits_and_separators(self):
        self.assertEqual(role_from_local_part("support2"), "Поддержка")
        self.assertEqual(role_from_local_part("sales.eu"), "Продажи")
        self.assertEqual(role_from_local_part("hr-moscow"), "Кадры")
        self.assertEqual(role_from_local_part("john.sales"), "Продажи")
        self.assertEqual(role_from_local_part("salesteam"), "Продажи")
        self.assertEqual(role_from_local_part("hrdepartment"), "Кадры")

    def test_a_person_has_no_role(self):
        for local in ("john.smith", "anna", "zogbinanatol1", "leo.fontanieu",
                      "rachaeldakoalagirl", "j.smith", "michael.bauer"):
            with self.subTest(local=local):
                self.assertEqual(role_from_local_part(local), "")

    def test_lookalikes_do_not_match(self):
        for local in ("information", "devine", "helpful", "salesman",
                      "director777x", "adminster"):
            with self.subTest(local=local):
                self.assertEqual(role_from_local_part(local), "",
                                 "подстрока превратила имя в должность")

    def test_garbage_gives_empty(self):
        for junk in (None, "", "   ", 0, [], {}, b"sales", 3.5):
            with self.subTest(junk=junk):
                self.assertEqual(role_from_local_part(junk), "")


class TestEnrichTogether(unittest.TestCase):
    def test_corporate_role_address(self):
        result = enrich_org_role("sales@acme-corp.com", "Corporate")
        self.assertEqual(result["company"], "Acme Corp")
        self.assertEqual(result["job_role"], "Продажи")
        self.assertEqual(result["company_source"], "домен")
        self.assertEqual(result["job_role_source"], "адрес")

    def test_corporate_person(self):
        result = enrich_org_role("rnair@veltrano.com", "Corporate")
        self.assertEqual(result["company"], "Veltrano")
        self.assertEqual(result["job_role"], "")
        self.assertEqual(result["job_role_source"], "",
                         "пустая должность помечена источником — "
                         "источник обязан быть только у заполненного поля")

    def test_free_provider_person_gets_nothing(self):
        result = enrich_org_role("john.smith@gmail.com", "Personal")
        self.assertEqual(result, {"company": "", "job_role": "",
                                  "company_source": "", "job_role_source": ""})

    def test_free_provider_role_still_gets_the_role(self):
        result = enrich_org_role("sales@gmail.com", "Personal")
        self.assertEqual(result["company"], "")
        self.assertEqual(result["job_role"], "Продажи")

    def test_broken_input_does_not_crash(self):
        for junk in (None, "", "no-at-sign", 0, [], {}, b"a@b.com"):
            with self.subTest(junk=junk):
                result = enrich_org_role(junk, "Corporate")
                self.assertEqual(set(result),
                                 {"company", "job_role", "company_source",
                                  "job_role_source"})


class TestRoleTableIsSane(unittest.TestCase):
    def test_every_role_has_a_readable_name(self):
        for key, value in JOB_ROLES.items():
            with self.subTest(key=key):
                self.assertTrue(key.isalpha() and key.islower())
                self.assertTrue(value and value[0].isupper())


if __name__ == "__main__":
    unittest.main()
