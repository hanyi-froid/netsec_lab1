"""命令行入口：列出/运行场景、单步演示、批量对比。GUI 不可用时可完全用它完成演示。

用法（在项目根目录）：
    python -m mitmlab list
    python -m mitmlab run mitm            # 运行一个场景并打印过程与结论
    python -m mitmlab run mitm --step     # 单步：每次回车推进一步
    python -m mitmlab all                 # 运行全部场景并给出对照表
    python -m mitmlab matrix              # 攻击 × 防御配置对比矩阵
    python -m mitmlab experiments --csv results   # 自动化实验并导出 CSV
    python -m mitmlab perf [--quick]      # 性能分析
    python -m mitmlab gui                 # 启动图形界面
"""

import argparse
import os
import sys
import unicodedata

from . import experiments, perf
from .proto import events as ev
from .proto.identities import default_keyring
from .proto.scenarios import SCENARIO_BY_ID, SCENARIOS, World

# 默认不显示的事件：网络层投递与 recv 与 send/intercept 重复，--verbose 时才显示
_QUIET_HIDDEN = {ev.NET, ev.RECV}


def _print_events(events, verbose: bool) -> None:
    for e in events:
        if verbose or e.kind not in _QUIET_HIDDEN:
            print(ev.format_event(e))


def cmd_list(_args) -> int:
    print(f"{'ID':<22}{'类别':<8}场景")
    for s in SCENARIOS:
        print(f"{s.id:<22}{s.category:<8}{s.title}")
    return 0


def _header(scenario) -> None:
    print(f"== {scenario.title} ==")
    print(scenario.description)
    print(f"防御配置：{scenario.profile.describe()}    Evil 行为：{scenario.evil_mode.value}\n")


def cmd_run(args) -> int:
    if args.scenario not in SCENARIO_BY_ID:
        print(f"未知场景 {args.scenario!r}，可用场景：{', '.join(SCENARIO_BY_ID)}", file=sys.stderr)
        return 2
    scenario = SCENARIO_BY_ID[args.scenario]
    world = World(scenario, keyring=default_keyring(args.rsa_bits))
    _header(scenario)
    shown = 0
    while True:
        what = world.step()
        _print_events(world.log.events[shown:], args.verbose)
        shown = len(world.log.events)
        if what is None:
            break
        if args.step:
            try:
                input(f"  ↳ 已完成：{what}（回车继续）")
            except EOFError:  # 非交互环境下自动继续
                args.step = False
    result = world.analyze()
    print("\n---- 结果 ----")
    print(result.summary)
    print("密钥指纹：" + "  ".join(f"{k}={v}" for k, v in result.fingerprints.items() if v))
    return 0


def cmd_all(args) -> int:
    keyring = default_keyring(args.rsa_bits)
    print(f"{'场景':<22}{'防御配置':<28}{'攻击得逞':<10}{'正常通信':<10}与预期")
    mismatches = 0
    for s in SCENARIOS:
        r = World(s, keyring=keyring).run()
        ok = (r.attack_succeeded == s.attack_expected) and (r.communication_ok == s.comm_expected)
        mismatches += not ok
        print(f"{s.id:<22}{s.profile.describe():<28}{'是' if r.attack_succeeded else '否':<10}"
              f"{'是' if r.communication_ok else '否':<10}{'一致' if ok else '不一致'}")
    return 1 if mismatches else 0


def _display_width(s: str) -> int:
    """终端显示宽度：全角字符占 2 格，保证中文表格对齐。"""
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in s)


def format_table(rows: list, headers: dict = None) -> str:
    """把行字典列表渲染为对齐的文本表格；headers 为 {字段: 列标题}。"""
    headers = headers or {k: k for k in rows[0]}
    cells = [[str(h) for h in headers.values()]] + [
        [("是" if v is True else "否" if v is False else str(v)) for v in (row[k] for k in headers)]
        for row in rows]
    widths = [max(_display_width(r[i]) for r in cells) for i in range(len(headers))]
    lines = []
    for n, r in enumerate(cells):
        lines.append("  ".join(c + " " * (w - _display_width(c)) for c, w in zip(r, widths)).rstrip())
        if n == 0:
            lines.append("  ".join("-" * w for w in widths))
    return "\n".join(lines)


def cmd_matrix(args) -> int:
    rows = experiments.defense_matrix(default_keyring(args.rsa_bits))
    profiles = [p.name for p in experiments.PROFILE_LIST]
    table = []
    for attack in dict.fromkeys(r["attack"] for r in rows):
        row = {"attack": attack}
        for r in rows:
            if r["attack"] == attack:
                row[r["profile"]] = "攻击得逞 ✗" if r["attack_succeeded"] else "被阻止 ✓"
        table.append(row)
    print(format_table(table, {"attack": "攻击 \\ 防御", **{p: p for p in profiles}}))
    return 0


def cmd_experiments(args) -> int:
    keyring = default_keyring(args.rsa_bits)
    print("== 攻击 × 防御对比矩阵 ==")
    cmd_matrix(args)
    print("\n== 各场景重复运行（每次随机数不同）的稳定性 ==")
    rep = experiments.scenario_repeats(keyring, repeats=args.trials)
    print(format_table(rep))
    print("\n== 异常情况模拟：网络故障下的通信成功率 ==")
    faults = experiments.fault_experiment(keyring, trials=args.trials)
    print(format_table(faults))
    if args.csv:
        for name, rows in (("matrix", experiments.defense_matrix(keyring)), ("repeats", rep), ("faults", faults)):
            path = os.path.join(args.csv, f"{name}.csv")
            experiments.write_csv(path, rows)
            print(f"已写入 {path}")
    return 0


def cmd_perf(args) -> int:
    rows = perf.run_benchmarks(quick=args.quick)
    print(format_table(rows, {"item": "项目", "value": "数值", "unit": "单位"}))
    if args.csv:
        experiments.write_csv(args.csv, rows)
        print(f"已写入 {args.csv}")
    return 0


def cmd_gui(args) -> int:
    try:
        from .gui.app import main as gui_main
    except ModuleNotFoundError as exc:
        if exc.name not in {"tkinter", "_tkinter"}:
            raise
        print("图形界面需要 tkinter。可以先用 python -m mitmlab run normal 启动命令行演示。",
              file=sys.stderr)
        return 1
    return gui_main(rsa_bits=args.rsa_bits)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m mitmlab", description="中间人攻击与防御实验器")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="列出全部场景").set_defaults(func=cmd_list)

    def add_common(sp):
        sp.add_argument("--rsa-bits", type=int, default=2048, help="RSA 密钥位数（默认 2048）")

    run = sub.add_parser("run", help="运行单个场景")
    run.add_argument("scenario")
    run.add_argument("--step", action="store_true", help="单步执行，每步回车继续")
    run.add_argument("--verbose", action="store_true", help="同时显示网络层与接收事件")
    add_common(run)
    run.set_defaults(func=cmd_run)

    allp = sub.add_parser("all", help="运行全部场景并输出对照表")
    add_common(allp)
    allp.set_defaults(func=cmd_all)

    gui = sub.add_parser("gui", help="启动图形界面")
    add_common(gui)
    gui.set_defaults(func=cmd_gui)

    matrix = sub.add_parser("matrix", help="攻击×防御对比矩阵")
    add_common(matrix)
    matrix.set_defaults(func=cmd_matrix)

    exp = sub.add_parser("experiments", help="自动化实验：对比矩阵、重复稳定性、网络故障")
    exp.add_argument("--trials", type=int, default=10, help="每组重复/试验次数（默认 10）")
    exp.add_argument("--csv", metavar="DIR", help="把结果导出为 CSV 到该目录")
    add_common(exp)
    exp.set_defaults(func=cmd_experiments)

    pf = sub.add_parser("perf", help="性能分析")
    pf.add_argument("--quick", action="store_true", help="缩小规模，快速运行")
    pf.add_argument("--csv", metavar="FILE", help="导出为 CSV")
    pf.set_defaults(func=cmd_perf)
    return p


def main(argv=None) -> int:
    # 重定向到文件/管道时 Windows 默认编码可能不是 UTF-8，统一为 UTF-8 避免中文报错
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
