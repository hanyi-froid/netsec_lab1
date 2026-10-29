"""命令行入口：列出/运行场景、单步演示、批量对比。GUI 不可用时可完全用它完成演示。

用法（在项目根目录）：
    python -m mitmlab list
    python -m mitmlab run mitm            # 运行一个场景并打印过程与结论
    python -m mitmlab run mitm --step     # 单步：每次回车推进一步
    python -m mitmlab all                 # 运行全部场景并给出对照表
    python -m mitmlab gui                 # 启动图形界面
"""

import argparse
import sys

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


def cmd_gui(args) -> int:
    from .gui.app import main as gui_main  # 延迟导入：无 tkinter 的环境仍可使用 CLI
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
