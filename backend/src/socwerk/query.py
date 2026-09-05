from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .detection import field_value
from .models import ScenarioEvent


class QueryError(ValueError):
    pass


TOKEN = re.compile(
    r"""\s*(?:(?P<quoted>"(?:[^"\\]|\\.)*")|(?P<op>!=|>=|<=|=|>|<|\(|\)|,)|(?P<word>[A-Za-z0-9_.:\-/]+))"""
)


def tokenize(source: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    while position < len(source):
        match = TOKEN.match(source, position)
        if not match:
            raise QueryError(f"Unexpected token at position {position}")
        token = match.group("quoted") or match.group("op") or match.group("word")
        tokens.append(token)
        position = match.end()
    return tokens


def scalar(token: str) -> Any:
    if token.startswith('"'):
        return bytes(token[1:-1], "utf-8").decode("unicode_escape")
    lowered = token.casefold()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return float(token) if "." in token else int(token)
    except ValueError:
        return token


Predicate = Callable[[ScenarioEvent], bool]


@dataclass
class Parser:
    tokens: list[str]
    index: int = 0

    def peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise QueryError("Unexpected end of query")
        self.index += 1
        return token

    def expression(self) -> Predicate:
        left = self.term()
        while (token := self.peek()) and token.casefold() == "or":
            self.take()
            right = self.term()
            previous = left

            def either(event: ScenarioEvent, a: Predicate = previous, b: Predicate = right) -> bool:
                return a(event) or b(event)

            left = either
        return left

    def term(self) -> Predicate:
        left = self.factor()
        while (token := self.peek()) and token.casefold() == "and":
            self.take()
            right = self.factor()
            previous = left

            def both(event: ScenarioEvent, a: Predicate = previous, b: Predicate = right) -> bool:
                return a(event) and b(event)

            left = both
        return left

    def factor(self) -> Predicate:
        if self.peek() == "(":
            self.take()
            result = self.expression()
            if self.take() != ")":
                raise QueryError("Expected closing parenthesis")
            return result
        if (self.peek() or "").casefold() == "contains":
            self.take()
            if self.take() != "(":
                raise QueryError("Expected '(' after contains")
            field = self.take()
            if self.take() != ",":
                raise QueryError("Expected ',' in contains")
            needle = scalar(self.take())
            if self.take() != ")":
                raise QueryError("Expected ')' after contains")
            return lambda event: (
                str(needle).casefold() in str(field_value(event, field) or "").casefold()
            )
        field = self.take()
        operator = self.take()
        if operator not in {"=", "!=", ">", "<", ">=", "<="}:
            raise QueryError(f"Unsupported operator: {operator}")
        expected = scalar(self.take())

        def compare(event: ScenarioEvent) -> bool:
            actual = field_value(event, field)
            if operator == "=":
                if isinstance(actual, list):
                    return expected in actual
                return str(actual or "").casefold() == str(expected).casefold()
            if operator == "!=":
                return str(actual or "").casefold() != str(expected).casefold()
            try:
                a, b = float(actual), float(expected)
            except (TypeError, ValueError):
                a, b = str(actual or ""), str(expected)
            return {">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}[operator]

        return compare


def compile_query(source: str) -> Predicate:
    if len(source) > 1000:
        raise QueryError("Query exceeds 1000 characters")
    tokens = tokenize(source)
    if not tokens:
        return lambda _event: True
    parser = Parser(tokens)
    predicate = parser.expression()
    if parser.peek() is not None:
        raise QueryError(f"Unexpected token: {parser.peek()}")
    return predicate
