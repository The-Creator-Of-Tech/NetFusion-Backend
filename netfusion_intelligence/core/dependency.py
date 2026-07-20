"""
Feed Dependency Resolver, Dependency Graph, and Topological Sorting Engine.
Detects dependency cycles, computes execution order, and validates prerequisites.
"""

from typing import Dict, List, Optional, Set, Tuple
from netfusion_intelligence.core.exceptions import IntelligenceException
from netfusion_intelligence.interfaces.feed import FeedInterface
from netfusion_intelligence.models.health import FeedHealth, FeedHealthStatus


class DependencyCycleError(IntelligenceException):
    """Raised when a circular dependency is detected among feeds."""
    pass


class DependencyUnavailableError(IntelligenceException):
    """Raised when a prerequisite feed is not registered or unavailable."""
    pass


class FeedDependencyGraph:
    """
    Manages feed dependencies, detects cycles, calculates topological execution order,
    and checks prerequisite health.
    """

    def __init__(self, feeds: Optional[List[FeedInterface]] = None):
        self._feeds: Dict[str, FeedInterface] = {}
        if feeds:
            for feed in feeds:
                self.add_feed(feed)

    def add_feed(self, feed: FeedInterface) -> None:
        """Add a feed to the graph."""
        self._feeds[feed.feed_id] = feed

    def get_dependencies(self, feed_id: str) -> List[str]:
        """Get declared direct dependency feed IDs for a given feed."""
        if feed_id not in self._feeds:
            return []
        manifest = self._feeds[feed_id].manifest
        return manifest.dependencies if manifest else []

    def detect_cycles(self) -> List[List[str]]:
        """
        Detects circular dependencies in the graph using Depth-First Search.
        Returns a list of cycle paths if any exist.
        """
        visited: Set[str] = set()
        rec_stack: Set[str] = set()
        cycles: List[List[str]] = []

        def dfs(node: str, path: List[str]):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            deps = self.get_dependencies(node)
            for dep in deps:
                if dep not in visited:
                    if dep in self._feeds:
                        dfs(dep, path[:])
                elif dep in rec_stack:
                    cycle_start = path.index(dep) if dep in path else 0
                    cycles.append(path[cycle_start:] + [dep])

            rec_stack.remove(node)

        for feed_id in self._feeds:
            if feed_id not in visited:
                dfs(feed_id, [])

        return cycles

    def get_topological_order(self) -> List[str]:
        """
        Returns topological sorting of registered feed IDs (execution order).
        Dependencies come before dependents.
        Raises DependencyCycleError if cycles are detected.
        """
        cycles = self.detect_cycles()
        if cycles:
            cycle_str = " -> ".join(cycles[0])
            raise DependencyCycleError(f"Circular dependency detected in intelligence feeds: {cycle_str}")

        in_degree: Dict[str, int] = {f: 0 for f in self._feeds}
        adj: Dict[str, List[str]] = {f: [] for f in self._feeds}

        for feed_id in self._feeds:
            deps = self.get_dependencies(feed_id)
            for dep in deps:
                if dep in self._feeds:
                    adj[dep].append(feed_id)
                    in_degree[feed_id] += 1

        # Kahn's algorithm
        queue = [f for f, deg in in_degree.items() if deg == 0]
        order = []

        while queue:
            node = queue.pop(0)
            order.append(node)
            for neighbor in adj[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(order) != len(self._feeds):
            raise DependencyCycleError("Circular dependency detected during topological sort")

        return order

    def validate_prerequisites(self, feed_id: str, health_map: Optional[Dict[str, FeedHealth]] = None) -> Tuple[bool, Optional[str]]:
        """
        Verifies if all prerequisite dependencies for feed_id are available and healthy.
        Returns (is_satisfied, error_reason).
        """
        if feed_id not in self._feeds:
            return False, f"Feed '{feed_id}' is not registered"

        deps = self.get_dependencies(feed_id)
        for dep_id in deps:
            if dep_id not in self._feeds:
                return False, f"Prerequisite feed '{dep_id}' is not registered"
            
            if health_map and dep_id in health_map:
                dep_health = health_map[dep_id]
                if dep_health.status == FeedHealthStatus.UNHEALTHY:
                    return False, f"Prerequisite feed '{dep_id}' is UNHEALTHY"

        return True, None
