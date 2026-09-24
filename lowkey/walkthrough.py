            src, line = source_map.get(sig, (None, None))
            functions.append(
                FunctionInfo(
                    contract=name,
                    name=str(item.get("name") or ""),
                    inputs=item.get("inputs") or [],
                    outputs=item.get("outputs") or [],
                    mutability=str(item.get("stateMutability") or "nonpayable"),
                    signature=sig,
                    source=src,
                    line=line,
                    body=(
                        next(
                            (
                                f.body
                                for f in (ci.functions if ci else [])
                                if f.signature == sig
                            ),
                            "",
                        )
                    ),
                    modifiers=(
                        next(
                            (
                                f.modifiers
                                for f in (ci.functions if ci else [])
                                if f.signature == sig
                            ),
                            [],
                        )
                    ),
                    calls=(
                        next(
                            (
                                f.calls
                                for f in (ci.functions if ci else [])
                                if f.signature == sig
                            ),
                            [],
                        )
                    ),
                    visibility=next(
                        (
                            f.visibility
                            for f in (ci.functions if ci else [])
                            if f.signature == sig and f.visibility != "unknown"
                        ),
                        "unknown",
                    ),
                    reads=next(
                        (
                            f.reads
                            for f in (ci.functions if ci else [])
                            if f.signature == sig
                        ),
                        [],
                    ),
                    writes=next(
                        (
                            f.writes
                            for f in (ci.functions if ci else [])
                            if f.signature == sig
                        ),
                        [],
                    ),
                    array_ops=next(
                        (
                            f.array_ops
                            for f in (ci.functions if ci else [])
                            if f.signature == sig
                        ),
                        [],
                    ),
                )
            )
        by_contract[name] = functions
    return by_contract


def _source_link(root: Path, source: str | None, line: int | None, text: str) -> str:
    if not source or not line:
        return text
    path = (root / source).resolve()