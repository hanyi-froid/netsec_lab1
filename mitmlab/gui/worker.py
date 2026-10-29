"""后台任务执行器：线程安全地把耗时计算（RSA 密钥生成、批量实验）与界面刷新分开。

约定：工作线程只做纯计算，结果放进 queue.Queue；界面主线程用 root.after() 周期性调用
drain()，在主线程里执行回调并更新控件。工作线程绝不直接触碰任何 tkinter 控件
（tkinter 不是线程安全的）。本模块不依赖 tkinter，便于单独测试。
"""

import queue
import threading
from typing import Callable


class BackgroundRunner:
    def __init__(self):
        self._results: queue.Queue = queue.Queue()

    def submit(self, work: Callable[[], object], on_done: Callable[[object], None],
               on_error: Callable[[BaseException], None] = None) -> threading.Thread:
        """在守护线程中执行 work()；结果经队列交给 drain() 所在线程回调。"""
        def target():
            try:
                outcome = (on_done, work())
            except BaseException as exc:  # 异常也要交回主线程处理，不能静默丢失
                outcome = (on_error or _raise_in_main, exc)
            self._results.put(outcome)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        return thread

    def drain(self) -> int:
        """在调用者线程（界面主线程）中执行所有已完成任务的回调，返回处理条数。"""
        count = 0
        while True:
            try:
                callback, payload = self._results.get_nowait()
            except queue.Empty:
                return count
            callback(payload)
            count += 1


def _raise_in_main(exc: BaseException) -> None:
    raise exc
