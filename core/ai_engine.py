from core.heuristics import local_part_entropy, looks_machine_generated


class EmailAI:
    def __init__(self):
        self.is_trained = True

    def train_models(self):
        self.is_trained = True
        return True

    def predict(self, email):
        if not isinstance(email, str) or "@" not in email:
            return False
        return looks_machine_generated(email)
