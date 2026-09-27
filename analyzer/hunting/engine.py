from .models import (
    HUNTING_FIELDS,
    HUNTING_OPERATORS,
    HUNTING_SORT_FIELDS,
    HuntingQuery,
    HuntingQueryGroup,
    HuntingTimeRange,
    HuntingSearch,
)


class ThreatHuntingEngine:

    def search(self, events, query):
        results = []

        for event in events:
            if isinstance(query, HuntingQuery):
                matches = self._matches(event, query)

            elif isinstance(query, HuntingQueryGroup):
                matches = self._matches_group(event, query)

            elif isinstance(query, HuntingTimeRange):
                matches = self._matches_time_range(event, query)

            elif isinstance(query, HuntingSearch):
                matches = self._matches_search(event, query)

            else:
                matches = False

            if matches:
                results.append(event)

        if isinstance(query, HuntingSearch):
            results = self._sort_results(
                results,
                query.sort_by,
                query.sort_order,
            )

            results = results[:query.limit]

        return results

    @staticmethod
    def _matches_search(event, search):
        if search.conditions is not None:
            if isinstance(search.conditions, HuntingQuery):
                if not ThreatHuntingEngine._matches(
                    event,
                    search.conditions,
                ):
                    return False

            elif isinstance(search.conditions, HuntingQueryGroup):
                if not ThreatHuntingEngine._matches_group(
                    event,
                    search.conditions,
                ):
                    return False

            else:
                return False

        if search.time_range is not None:
            if not ThreatHuntingEngine._matches_time_range(
                event,
                search.time_range,
            ):
                return False

        return True

    @staticmethod
    def _matches_group(event, query_group):
        if query_group.logic.upper() not in {"AND", "OR"}:
            return False

        results = [
            ThreatHuntingEngine._matches(event, query)
            for query in query_group.queries
        ]

        if query_group.logic.upper() == "AND":
            return all(results)

        return any(results)

    @staticmethod
    def _matches_time_range(event, query):
        timestamp = event.get("timestamp")

        if timestamp is None:
            return False

        if not hasattr(timestamp, "timestamp"):
            return False

        return query.start <= timestamp <= query.end

    @staticmethod
    def _sort_results(events, sort_by, sort_order):
        if sort_by not in HUNTING_SORT_FIELDS:
            return []

        if sort_order.lower() not in {"asc", "desc"}:
            return []

        def sort_key(event):
            value = event.get(sort_by)

            if value is None:
                return ""

            return value

        return sorted(
            events,
            key=sort_key,
            reverse=sort_order.lower() == "desc",
        )

    @staticmethod
    def _matches(event, query):
        if query.field not in HUNTING_FIELDS:
            return False

        if query.operator not in HUNTING_OPERATORS:
            return False

        field_value = event.get(query.field)

        if field_value is None:
            return False

        field_value = str(field_value).lower()
        query_value = str(query.value).lower()

        if query.operator == "equals":
            return field_value == query_value

        if query.operator == "not_equals":
            return field_value != query_value

        if query.operator == "contains":
            return query_value in field_value

        if query.operator in {
            "greater_than",
            "less_than",
            "greater_than_or_equal",
            "less_than_or_equal",
        }:
            try:
                field_number = float(field_value)
                query_number = float(query_value)
            except (TypeError, ValueError):
                return False

            if query.operator == "greater_than":
                return field_number > query_number

            if query.operator == "less_than":
                return field_number < query_number

            if query.operator == "greater_than_or_equal":
                return field_number >= query_number

            if query.operator == "less_than_or_equal":
                return field_number <= query_number

        return False