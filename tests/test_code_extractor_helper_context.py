# ruff: noqa: S101
from pathlib import Path

from benchmarks.runner.code_extractor import (
    CodeVariant,
    extract_code_for_case,
    limit_extracted_code_for_variant,
)
from benchmarks.runner.models import (
    BenchmarkCase,
    CodeLocation,
    Finding,
    FindingKind,
    Language,
)


def test_morefixes_ruby_helper_context_attaches_referenced_helpers(
    tmp_path: Path,
) -> None:
    case = _morefixes_case(["address.rb", "addressbook_controller.rb"])
    snapshot_dir = tmp_path / "morefixes" / case.case_id / "code" / "patched"
    snapshot_dir.mkdir(parents=True)
    (snapshot_dir / "address.rb").write_text(
        "\n".join(
            [
                "class Address",
                "  def self.get_by_email(mail_addr)",
                "    SqlHelper.validate_token([mail_addr])",
                "    AddressbookHelper.get_scope_condition_for(user)",
                "    Address.where(\"email1='#{mail_addr}'\")",
                "  end",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (snapshot_dir / "addressbook_controller.rb").write_text(
        "\n".join(
            [
                "class AddressbookController",
                "  def list",
                "    SqlHelper.validate_token([params[:sort_col]])",
                "    sql = 'select * from addresses order by ' + params[:sort_col]",
                "    paginate_by_sql(Address, sql, 50)",
                "  end",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (snapshot_dir / "sql_helper.rb").write_text(
        "module SqlHelper\n  def self.validate_token(tokens)\n    true\n  end\nend\n",
        encoding="utf-8",
    )
    (snapshot_dir / "addressbook_helper.rb").write_text(
        (
            "module AddressbookHelper\n"
            "  def self.get_scope_condition_for(user)\n"
            "    '(owner_id=0)'\n"
            "  end\n"
            "end\n"
        ),
        encoding="utf-8",
    )

    pieces = extract_code_for_case(
        case,
        CodeVariant.PATCHED,
        tmp_path,
        include_helper_context=True,
    )

    by_file = {piece.file_path: piece for piece in pieces}
    assert sorted(by_file) == ["address.rb", "addressbook_controller.rb"]
    assert [context.file_path for context in by_file["address.rb"].context_files] == [
        "sql_helper.rb",
        "addressbook_helper.rb",
    ]
    assert [
        context.file_path
        for context in by_file["addressbook_controller.rb"].context_files
    ] == ["sql_helper.rb"]


def test_helper_context_survives_primary_file_cap(tmp_path: Path) -> None:
    case = _morefixes_case(["desktop_controller.rb", "address.rb"])
    snapshot_dir = tmp_path / "morefixes" / case.case_id / "code" / "patched"
    snapshot_dir.mkdir(parents=True)
    (snapshot_dir / "desktop_controller.rb").write_text(
        "class DesktopController\n  def index\n    render\n  end\nend\n",
        encoding="utf-8",
    )
    (snapshot_dir / "address.rb").write_text(
        (
            "class Address\n"
            "  def self.get_by_email(mail_addr)\n"
            "    SqlHelper.validate_token([mail_addr])\n"
            "    Address.where(\"email1='#{mail_addr}'\")\n"
            "  end\n"
            "end\n"
        ),
        encoding="utf-8",
    )
    (snapshot_dir / "sql_helper.rb").write_text(
        "module SqlHelper\n  def self.validate_token(tokens)\n    true\n  end\nend\n",
        encoding="utf-8",
    )

    pieces = extract_code_for_case(
        case,
        CodeVariant.PATCHED,
        tmp_path,
        include_helper_context=True,
    )
    capped = limit_extracted_code_for_variant(
        pieces,
        1,
        case=case,
        variant=CodeVariant.PATCHED,
    )

    assert [piece.file_path for piece in capped] == ["address.rb"]
    assert [context.file_path for context in capped[0].context_files] == [
        "sql_helper.rb"
    ]


def test_helper_context_skips_unrelated_generic_helper_refs(tmp_path: Path) -> None:
    case = _morefixes_case(["desktop_controller.rb"])
    snapshot_dir = tmp_path / "morefixes" / case.case_id / "code" / "patched"
    snapshot_dir.mkdir(parents=True)
    (snapshot_dir / "desktop_controller.rb").write_text(
        "\n".join(
            [
                "class DesktopController",
                "  def list",
                "    ApplicationHelper.get_config_yaml",
                "    SqlHelper.validate_token([params[:group_id]])",
                "  end",
                "end",
            ]
        ),
        encoding="utf-8",
    )
    (snapshot_dir / "application_helper.rb").write_text(
        "module ApplicationHelper\n  def self.get_config_yaml\n    {}\n  end\nend\n",
        encoding="utf-8",
    )
    (snapshot_dir / "sql_helper.rb").write_text(
        "module SqlHelper\n  def self.validate_token(tokens)\n    true\n  end\nend\n",
        encoding="utf-8",
    )

    pieces = extract_code_for_case(
        case,
        CodeVariant.PATCHED,
        tmp_path,
        include_helper_context=True,
    )

    assert [context.file_path for context in pieces[0].context_files] == [
        "sql_helper.rb"
    ]


def _morefixes_case(files: list[str]) -> BenchmarkCase:
    return BenchmarkCase(
        case_id="morefixes-CVE-2099-0001-example",
        project="example/project",
        language=Language.RUBY,
        vulnerable_version="before",
        patched_version="after",
        source_dataset="morefixes",
        ground_truth=[
            Finding(
                cwe_id="CWE-89",
                kind=FindingKind.PASS,
                location=CodeLocation(file=file, start_line=1, end_line=5),
            )
            for file in files
        ],
    )
