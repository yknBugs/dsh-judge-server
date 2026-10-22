"""规则清单与等级映射：判定器需要知道"有哪些规则名"以及"四个等级怎么叫"。

**这个文件不放文案。** 卡片上的每一句话都在 `writers.py`，要改文字请改那边。

这里只有三件事：

* `LEVEL_LABEL` —— 分析器的等级名到卡片上的四个词；
* `JUDGE_ERROR_RULE` —— 判定器自己那条"分析器崩了"的规则名。它不属于分析器的目录，所以
  在 `writers.py` 里单独登记；
* `INFORMATIONAL` —— 纯统计类的检查项（写了多少字节、文件大小变化）。它们值得显示，但不该
  成为需要审批的理由。
"""

from __future__ import annotations

#: 分析器的等级名 -> 卡片上的标签。四等级对应三判定的映射见 `policy.py`。
LEVEL_LABEL = {"BLOCK": "拦截", "HIGH": "警告", "MEDIUM": "注意", "LOW": "提示", "NONE": "无"}

#: 等级次序，用于排序与取最严重的一条。
LEVEL_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "BLOCK": 4}

#: 判定器自己那条规则：分析器在检查这次调用时抛异常。它描述的是判定器，不是分析器的规则，
#: 所以不在分析器的规则目录里。
JUDGE_ERROR_RULE = "analyzer-error"

#: 判定器自有的检查项规则名（`write`/`edit` 的目标类检查，以及工具名与语法不一致）。这些也
#: 不在分析器的规则目录里，`test_catalog_coverage` 会把它们排除掉，不算"过期条目"。
JUDGE_OWN_RULES: frozenset[str] = frozenset(
    {
        JUDGE_ERROR_RULE,
        "write-size",
        "edit-size-change",
        "write-target-is-directory",
        "edit-target-missing",
        "edit-target-not-utf8",
        "edit-target-unreadable",
        "write-target-unreadable",
        "edit-empty-fragment",
        "edit-fragment-missing",
        "edit-fragment-ambiguous",
        "edit-no-change",
        "command-tool-mismatch",
        "cwd-outside-workspace",
        "tool-needs-confirmation",
        "search-request",
    }
)

#: 纯统计，不是风险：值得显示，但不构成需要审批的理由。
INFORMATIONAL: frozenset[str] = frozenset({"write-size", "edit-size-change", "edit-no-change"})


def label_for(level: str) -> str:
    """等级名 -> 卡片标签。没登记的等级原样返回，方便发现分析器加了新等级。"""
    return LEVEL_LABEL.get(level.upper(), level)


def known_rules() -> frozenset[str]:
    """所有有文案的规则名。文案在 `writers.py`，这里只是转发，免得调用方两边都要 import。"""
    from writers import known_writers

    return known_writers()
