"""
Tests for NetFusion PromptBuilder and security prompt templates.
"""

import pytest

from netfusion_ai import PromptBuilder, PromptTemplateType, PromptTemplateError


def test_prompt_builder_rendering_all_templates():
    pb = PromptBuilder()
    context_md = "### Context: Sample Incident"

    for tmpl in PromptTemplateType:
        req = pb.build_prompt(
            template_type=tmpl,
            context_markdown=context_md,
            user_query="Evaluate findings.",
        )
        assert req.system_prompt is not None
        assert "MANDATORY SAFETY PRINCIPLES" in req.system_prompt
        assert context_md in req.user_prompt
        assert "Evaluate findings." in req.user_prompt


def test_prompt_builder_invalid_template():
    pb = PromptBuilder()
    with pytest.raises(PromptTemplateError):
        pb.build_prompt(
            template_type="NON_EXISTENT_TEMPLATE",  # type: ignore
            context_markdown="test",
        )
