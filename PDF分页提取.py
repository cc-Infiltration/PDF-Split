import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PyPDF2 import PdfReader, PdfWriter
from typing import List, Optional, Tuple
import os
import re
import math


class PathSecurity:
    """路径安全验证工具类"""

    # 禁止访问的系统路径模式
    BLOCKED_PATTERNS = [
        r'^[/\\]?etc',
        r'^[/\\]?sys',
        r'^[/\\]?proc',
        r'^[/\\]?dev',
        r'^[/\\]?boot',
        r'^[/\\]?root',
        r'^[/\\]?sbin',
        r'^[/\\]?bin',
        r'^[/\\]?lib',
        r'^[/\\]?lib64',
        r'^[/\\]?usr[/\\]bin',
        r'^[/\\]?usr[/\\]sbin',
        r'^[/\\]?windows[/\\]system32',
        r'^[/\\]?windows[/\\]system',
        r'[/\\]\.\.[/\\]',  # 路径穿越尝试
        r'^~\/?$',  # 用户目录简写
    ]

    # Windows系统保护路径（只保护真正的系统目录）
    # WINDOWS: 核心系统目录
    # SYSTEM VOLUME INFORMATION: 系统还原信息目录
    # $RECYCLE.BIN: 回收站目录
    # 注意：Program Files是应用程序安装目录，用户有权访问其中的文件
    WINDOWS_PROTECTED_PATHS = [
        'C:\\WINDOWS',
        'C:\\SYSTEM VOLUME INFORMATION',
        'C:\\$RECYCLE.BIN',
    ]

    @classmethod
    def normalize_path(cls, path: str) -> str:
        """规范化文件路径

        Args:
            path: 输入路径

        Returns:
            规范化后的路径
        """
        if not path:
            return ""

        # 转换为绝对路径
        abs_path = os.path.abspath(path)

        # 统一分隔符
        normalized = abs_path.replace('/', '\\')

        # 移除多余的点和反斜线
        while '\\\\' in normalized:
            normalized = normalized.replace('\\\\', '\\')

        # 处理 ~ 用户目录
        if normalized.startswith('~'):
            normalized = os.path.expanduser(normalized)

        return normalized

    @classmethod
    def validate_path(cls, path: str) -> Tuple[bool, str]:
        """验证路径安全性

        Args:
            path: 待验证的路径

        Returns:
            (是否安全, 错误消息)
        """
        if not path:
            return False, "路径不能为空"

        # 检查路径长度
        if len(path) > 260:
            return False, "路径长度超过系统限制（260字符）"

        # 规范化路径
        normalized = cls.normalize_path(path)

        # Windows系统：驱动器盘符后的冒号是合法的（如 C:\ 或 D:/）
        # 需要先提取驱动器部分再检查非法字符
        if os.name == 'nt':
            # 分离驱动器部分（如 C:\）和其他部分
            drive_match = re.match(r'^([A-Za-z]:[/\\]?)(.*)$', normalized)
            if drive_match:
                path_without_drive = drive_match.group(2)
            else:
                path_without_drive = normalized

            # 在非驱动器部分检查非法字符
            illegal_chars = ['<', '>', '"', '|', '?', '*']
            for char in illegal_chars:
                if char in path_without_drive:
                    return False, f"路径包含非法字符: {char}"
        else:
            # 非Windows系统检查所有非法字符
            illegal_chars = ['<', '>', ':', '"', '|', '?', '*']
            for char in illegal_chars:
                if char in normalized:
                    return False, f"路径包含非法字符: {char}"

        # 检查路径穿越模式
        for pattern in cls.BLOCKED_PATTERNS:
            if re.match(pattern, normalized, re.IGNORECASE):
                return False, "禁止访问系统保护路径"

        # Windows特殊检查
        if os.name == 'nt':
            # 检查保护路径
            normalized_upper = normalized.upper()
            # 检查是否以受保护路径开头
            for protected in cls.WINDOWS_PROTECTED_PATHS:
                # 使用startswith确保只匹配真正的系统目录
                if normalized_upper.startswith(protected):
                    return False, "禁止访问系统保护目录"

            # 检查驱动器访问
            drive = os.path.splitdrive(normalized)[0]
            if not drive:
                return False, "路径必须包含驱动器盘符"

        # 检查是否在可写目录
        output_dir = os.path.dirname(normalized)
        if output_dir and not os.access(output_dir, os.W_OK):
            return False, "输出目录无写入权限"

        return True, ""

    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """清理文件名，移除非法字符

        Args:
            filename: 原始文件名

        Returns:
            清理后的文件名
        """
        if not filename:
            return "unnamed"

        # 移除或替换非法字符
        illegal_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*']
        sanitized = filename
        for char in illegal_chars:
            sanitized = sanitized.replace(char, '_')

        # 移除前后空格和点
        sanitized = sanitized.strip('. ')

        # 确保不为空
        if not sanitized:
            return "未命名"

        # 限制文件名长度
        if len(sanitized) > 200:
            name, ext = os.path.splitext(sanitized)
            sanitized = name[:200-len(ext)] + ext

        return sanitized


class ValidationUtils:
    """输入验证工具类"""

    # 最大文件大小（2GB）
    MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024

    @classmethod
    def validate_file_path(cls, path: str) -> Tuple[bool, str]:
        """验证文件路径

        Args:
            path: 文件路径

        Returns:
            (是否有效, 错误消息)
        """
        if not path:
            return False, "文件路径不能为空"

        # 路径安全检查
        is_safe, error_msg = PathSecurity.validate_path(path)
        if not is_safe:
            return False, error_msg

        # 检查文件是否存在
        if not os.path.exists(path):
            return False, "文件不存在"

        # 检查是否为文件
        if not os.path.isfile(path):
            return False, "路径不是有效的文件"

        # 检查是否为PDF文件
        if not path.lower().endswith('.pdf'):
            return False, "只支持PDF文件格式"

        # 检查文件大小
        try:
            file_size = os.path.getsize(path)
            if file_size == 0:
                return False, "文件为空"
            if file_size > cls.MAX_FILE_SIZE:
                max_size_mb = cls.MAX_FILE_SIZE / (1024 * 1024)
                return False, f"文件超过{max_size_mb:.0f}MB限制"
        except OSError as e:
            return False, f"无法读取文件大小: {str(e)}"

        return True, ""

    @classmethod
    def validate_output_path(cls, path: str) -> Tuple[bool, str]:
        """验证输出路径

        Args:
            path: 输出文件路径

        Returns:
            (是否有效, 错误消息)
        """
        if not path:
            return False, "输出路径不能为空"

        # 路径安全检查
        is_safe, error_msg = PathSecurity.validate_path(path)
        if not is_safe:
            return False, error_msg

        # 确保为PDF格式
        if not path.lower().endswith('.pdf'):
            return False, "输出文件必须是PDF格式"

        # 检查目录是否可写
        output_dir = os.path.dirname(path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError:
                return False, "无法创建输出目录"

        # 检查磁盘空间（粗略估计）
        try:
            if output_dir:
                disk_stats = os.statvfs(output_dir) if hasattr(os, 'statvfs') else None
                if disk_stats:
                    free_space = disk_stats.f_bavail * disk_stats.f_frsize
                    if free_space < 1024 * 1024:  # 少于1MB
                        return False, "磁盘空间不足"
        except Exception:
            pass

        return True, ""

    @classmethod
    def validate_page_range(cls, pages_text: str, total_pages: int) -> Tuple[bool, List[int], str]:
        """验证页码范围

        Args:
            pages_text: 页码范围字符串
            total_pages: PDF总页数

        Returns:
            (是否有效, 有效页码列表, 错误消息)
        """
        if not pages_text:
            return False, [], "页码范围不能为空"

        pages = []

        # 解析页码格式
        parts = pages_text.split(',')
        for part in parts:
            part = part.strip()
            if not part:
                continue

            # 范围格式（如 1-5）
            if '-' in part:
                try:
                    start, end = part.split('-', 1)
                    start_page = int(start.strip())
                    end_page = int(end.strip())

                    # 验证范围有效性
                    if start_page < 1:
                        return False, [], f"起始页码必须大于等于1"
                    if end_page > total_pages:
                        return False, [], f"结束页码({end_page})超过总页数({total_pages})"
                    if start_page > end_page:
                        return False, [], f"起始页码({start_page})大于结束页码({end_page})"

                    # 添加范围页码（转换为0-based索引）
                    pages.extend(range(start_page - 1, end_page))

                except ValueError:
                    return False, [], f"页码格式错误: {part}"
            else:
                # 单页格式
                try:
                    page_num = int(part)
                    if page_num < 1:
                        return False, [], f"页码必须大于等于1"
                    if page_num > total_pages:
                        return False, [], f"页码({page_num})超过总页数({total_pages})"
                    pages.append(page_num - 1)  # 转换为0-based索引
                except ValueError:
                    return False, [], f"页码格式错误: {part}"

        # 检查是否有重复页码
        if len(pages) != len(set(pages)):
            unique_pages = list(set(pages))
            duplicate_count = len(pages) - len(unique_pages)
            return True, sorted(unique_pages), f"（已自动去重，移除{duplicate_count}个重复页码）"

        return True, sorted(pages), ""


class PDFProcessor:
    """PDF处理引擎 - 优化大文件处理"""

    # 内存阈值：每100页触发一次内存释放检查
    MEMORY_CHECK_INTERVAL = 100

    def __init__(self):
        """初始化PDF处理器"""
        self.current_page = 0
        self.total_pages = 0
        self.pages_extracted = 0
        self._is_cancelled = False

    def get_pdf_info(self, file_path: str) -> Tuple[int, int]:
        """获取PDF基本信息

        Args:
            file_path: PDF文件路径

        Returns:
            (总页数, 文件大小MB)
        """
        try:
            reader = PdfReader(file_path)
            page_count = len(reader.pages)

            # 获取文件大小
            file_size = os.path.getsize(file_path)
            size_mb = file_size / (1024 * 1024)

            return page_count, size_mb
        except Exception as e:
            raise ValueError(f"无法读取PDF文件: {str(e)}")

    def extract_pages(
        self,
        input_path: str,
        output_path: str,
        pages: List[int],
        progress_callback: Optional[callable] = None
    ) -> Tuple[int, int, List[int]]:
        """提取PDF页面

        Args:
            input_path: 输入文件路径
            output_path: 输出文件路径
            pages: 要提取的页码列表（0-based）
            progress_callback: 进度回调函数，参数为 (当前页, 总页数, 百分比)

        Returns:
            (成功提取页数, 忽略页数, 被忽略的页码列表)
        """
        self._is_cancelled = False
        self.pages_extracted = 0

        try:
            # 打开输入文件
            reader = PdfReader(input_path)
            self.total_pages = len(reader.pages)

            # 创建输出文件
            writer = PdfWriter()

            # 有效和无效页码
            valid_pages = []
            invalid_pages = []

            # 第一遍：验证所有页码
            for page_num in pages:
                if 0 <= page_num < self.total_pages:
                    valid_pages.append(page_num)
                else:
                    invalid_pages.append(page_num)

            # 第二遍：提取页面
            total_to_extract = len(valid_pages)

            for idx, page_num in enumerate(valid_pages):
                if self._is_cancelled:
                    break

                writer.add_page(reader.pages[page_num])
                self.pages_extracted = idx + 1
                self.current_page = page_num

                # 触发进度回调
                if progress_callback:
                    progress = int((idx + 1) / total_to_extract * 100)
                    progress_callback(idx + 1, total_to_extract, progress)

                # 内存管理：定期释放内存
                if (idx + 1) % self.MEMORY_CHECK_INTERVAL == 0:
                    self._check_memory()

            # 写入输出文件
            with open(output_path, 'wb') as f:
                writer.write(f)

            # 清理
            writer.close()

            return self.pages_extracted, len(invalid_pages), invalid_pages

        except MemoryError:
            raise MemoryError("内存不足，无法处理大文件。请尝试分批处理。")
        except Exception as e:
            raise RuntimeError(f"PDF处理失败: {str(e)}")

    def _check_memory(self) -> None:
        """检查并释放内存"""
        import gc
        gc.collect()

    def cancel(self) -> None:
        """取消当前操作"""
        self._is_cancelled = True


class PDFExtractorApp:
    """PDF页码提取工具应用类 - 优化版"""

    def __init__(self, root: tk.Tk):
        """初始化应用"""
        self.root = root
        self.processor = PDFProcessor()
        self.total_pages = 0
        self.current_file_size = 0

        self._setup_styles()
        self._configure_window()
        self._build_ui()

    def _configure_window(self) -> None:
        """配置窗口属性"""
        self.root.title("PDF页码提取专业版")
        self.root.geometry("600x520")
        self.root.resizable(False, False)
        self.root.configure(bg=self.colors["background"])

    def _setup_styles(self) -> None:
        """设置样式配置"""
        self.colors = {
            "background": "#FFFFFF",
            "surface": "#f5f7fa",
            "border": "#dcdde6",
            "text_primary": "#2d3436",
            "text_secondary": "#a0a4ac",
            "accent": "#4a90e2",
            "success": "#2D7D46",
            "warning": "#B8860B",
            "error": "#C44536",
        }

        self.fonts = {
            "title": ("Segoe UI", 18, "bold"),
            "subtitle": ("Segoe UI", 11),
            "body": ("Segoe UI", 11),
            "small": ("Segoe UI", 8),
            "mono": ("Consolas", 11),
        }

        # 初始化 ttk 样式引擎
        self.style = ttk.Style()
        self.style.theme_use('clam')

        # 配置现代输入框样式
        self.style.configure('Modern.TEntry',
            fieldbackground=self.colors["surface"],
            foreground=self.colors["text_primary"],
            bordercolor=self.colors["border"],
            lightcolor=self.colors["border"],
            darkcolor=self.colors["border"],
            padding=10,
            font=self.fonts["body"]
        )

        # 配置状态切换
        self.style.map('Modern.TEntry',
            bordercolor=[('focus', self.colors["accent"]),
                        ('!focus', self.colors["border"])],
            lightcolor=[('focus', self.colors["accent"]),
                       ('!focus', self.colors["border"])],
            darkcolor=[('focus', self.colors["accent"]),
                      ('!focus', self.colors["border"])],
            fieldbackground=[('active', '#ffffff'),
                            ('!active', self.colors["surface"])]
        )

    def _build_ui(self) -> None:
        """构建用户界面"""
        self._create_header()
        self._create_main_content()
        self._create_footer()

    def _create_header(self) -> None:
        """创建标题区域"""
        header_frame = tk.Frame(self.root, bg=self.colors["background"], height=70)
        header_frame.pack(fill=tk.X, padx=32, pady=(20, 12))

        title_label = tk.Label(
            header_frame,
            text="PDF页码提取",
            font=self.fonts["title"],
            fg=self.colors["text_primary"],
            bg=self.colors["background"]
        )
        title_label.pack(anchor="w")

        subtitle_label = tk.Label(
            header_frame,
            text="支持大文件处理 | 智能页码验证 | 安全路径保护",
            font=self.fonts["small"],
            fg=self.colors["text_secondary"],
            bg=self.colors["background"]
        )
        subtitle_label.pack(anchor="w", pady=(2, 0))

    def _create_main_content(self) -> None:
        """创建主内容区域"""
        content_frame = tk.Frame(self.root, bg=self.colors["background"])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=32, pady=8)

        self._create_input_section(content_frame)
        self._create_info_section(content_frame)
        self._create_output_section(content_frame)
        self._create_pages_section(content_frame)
        self._create_progress_section(content_frame)
        self._create_extract_button(content_frame)

    def _create_input_section(self, parent: tk.Frame) -> None:
        """创建输入文件选择区域"""
        section = self._create_section_frame(parent)

        label = tk.Label(
            section,
            text="源文件",
            font=self.fonts["small"],
            fg=self.colors["text_secondary"],
            bg=self.colors["background"]
        )
        label.pack(anchor="w", pady=(0, 4))

        input_row = tk.Frame(section, bg=self.colors["background"])
        input_row.pack(fill=tk.X)

        self.input_entry = self._create_modern_entry(input_row, "请选择源PDF文件")

        self.input_button = self._create_file_button(input_row, "选择文件", self.select_input_pdf)
        self.input_button.pack(side=tk.RIGHT, padx=(8, 0))

    def _create_info_section(self, parent: tk.Frame) -> None:
        """创建文件信息展示区域"""
        info_frame = tk.Frame(parent, bg=self.colors["background"])
        info_frame.pack(fill=tk.X, pady=(0, 8))

        self.info_label = tk.Label(
            info_frame,
            text="",
            font=self.fonts["small"],
            fg=self.colors["accent"],
            bg=self.colors["background"]
        )
        self.info_label.pack(anchor="w")

    def _create_output_section(self, parent: tk.Frame) -> None:
        """创建输出文件选择区域"""
        section = self._create_section_frame(parent)

        label = tk.Label(
            section,
            text="保存位置",
            font=self.fonts["small"],
            fg=self.colors["text_secondary"],
            bg=self.colors["background"]
        )
        label.pack(anchor="w", pady=(0, 4))

        output_row = tk.Frame(section, bg=self.colors["background"])
        output_row.pack(fill=tk.X)

        self.output_entry = self._create_modern_entry(output_row, "请选择保存位置")

        self.output_button = self._create_file_button(output_row, "选择位置", self.select_output_pdf)
        self.output_button.pack(side=tk.RIGHT, padx=(8, 0))

    def _create_pages_section(self, parent: tk.Frame) -> None:
        """创建页码范围输入区域"""
        section = self._create_section_frame(parent)

        label = tk.Label(
            section,
            text="页码范围",
            font=self.fonts["small"],
            fg=self.colors["text_secondary"],
            bg=self.colors["background"]
        )
        label.pack(anchor="w", pady=(0, 4))

        pages_row = tk.Frame(section, bg=self.colors["background"])
        pages_row.pack(fill=tk.X)

        # 创建页码范围输入框（使用等宽字体）
        container = tk.Frame(pages_row, bg=self.colors["background"])
        container.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.pages_entry = ttk.Entry(
            container,
            style='Modern.TEntry',
            font=self.fonts["mono"]
        )
        self.pages_entry.pack(fill=tk.X, expand=True)
        
        # 实现占位文字功能
        placeholder = "请输入页码范围，例如：1-5, 7, 9-12"
        self.pages_entry.insert(0, placeholder)
        self.pages_entry.config(foreground=self.colors["text_secondary"])
        
        def on_focus_in(event):
            if self.pages_entry.get() == placeholder:
                self.pages_entry.delete(0, tk.END)
                self.pages_entry.config(foreground=self.colors["text_primary"])
        
        def on_focus_out(event):
            if not self.pages_entry.get():
                self.pages_entry.insert(0, placeholder)
                self.pages_entry.config(foreground=self.colors["text_secondary"])
        
        self.pages_entry.bind("<FocusIn>", on_focus_in)
        self.pages_entry.bind("<FocusOut>", on_focus_out)

        hint_label = tk.Label(
            section,
            text="格式示例: 1-5, 7, 9-12",
            font=self.fonts["small"],
            fg=self.colors["text_secondary"],
            bg=self.colors["background"]
        )
        hint_label.pack(anchor="w", pady=(4, 0))

    def _create_progress_section(self, parent: tk.Frame) -> None:
        """创建进度条区域"""
        progress_frame = tk.Frame(parent, bg=self.colors["background"])
        progress_frame.pack(fill=tk.X, pady=(8, 0))

        # 进度条背景
        self.progress_bg = tk.Frame(progress_frame, bg=self.colors["border"], height=6)
        self.progress_bg.pack(fill=tk.X)

        self.progress_fill = tk.Frame(self.progress_bg, bg=self.colors["accent"], height=6)
        self.progress_fill.pack(fill=tk.X, side=tk.LEFT)
        self.progress_fill.pack_forget()

        # 进度标签
        self.progress_label = tk.Label(
            progress_frame,
            text="",
            font=self.fonts["small"],
            fg=self.colors["text_secondary"],
            bg=self.colors["background"]
        )
        self.progress_label.pack(anchor="w", pady=(4, 0))

    def _create_extract_button(self, parent: tk.Frame) -> None:
        """创建提取按钮"""
        button_frame = tk.Frame(parent, bg=self.colors["background"])
        button_frame.pack(fill=tk.X, pady=(16, 0))

        self.extract_button = tk.Button(
            button_frame,
            text="开始提取",
            font=self.fonts["subtitle"],
            fg=self.colors["background"],
            bg=self.colors["text_primary"],
            activeforeground=self.colors["background"],
            activebackground=self.colors["text_secondary"],
            relief=tk.FLAT,
            bd=0,
            padx=32,
            pady=12,
            cursor="hand2",
            command=self.extract_pages
        )
        self.extract_button.pack()

        self._bind_button_events(self.extract_button)

    def _create_section_frame(self, parent: tk.Frame) -> tk.Frame:
        """创建区域容器"""
        frame = tk.Frame(parent, bg=self.colors["background"])
        frame.pack(fill=tk.X, pady=6)
        return frame

    def _create_file_button(self, parent: tk.Frame, text: str, command) -> tk.Button:
        """创建文件选择按钮"""
        btn = tk.Button(
            parent,
            text=text,
            font=self.fonts["small"],
            fg=self.colors["text_primary"],
            bg=self.colors["background"],
            activeforeground=self.colors["text_primary"],
            activebackground=self.colors["border"],
            relief=tk.SOLID,
            bd=1,
            padx=12,
            pady=6,
            cursor="hand2",
            command=command
        )
        return btn

    def _bind_button_events(self, button: tk.Button) -> None:
        """绑定按钮交互事件"""
        button.bind("<Enter>", lambda e: button.configure(
            bg=self.colors["text_secondary"] if button["bg"] == self.colors["text_primary"] else self.colors["border"]
        ))
        button.bind("<Leave>", lambda e: button.configure(
            bg=self.colors["text_primary"] if button["bg"] == self.colors["text_secondary"] else self.colors["background"]
        ))
        button.bind("<Button-1>", lambda e: button.configure(relief=tk.SUNKEN))
        button.bind("<ButtonRelease-1>", lambda e: button.configure(relief=tk.FLAT))

    def _on_rounded_entry_focus_out(self, entry: tk.Entry) -> None:
        """圆角输入框失焦事件"""
        if hasattr(entry, '_canvas') and hasattr(entry, '_normal_color'):
            entry._canvas.delete("all")
            self._draw_rounded_rect(
                entry._canvas, 0, 0,
                int(entry._canvas.cget("width")),
                int(entry._canvas.cget("height")),
                entry._corner_radius,
                entry._normal_color
            )

    def _create_modern_entry(self, parent: tk.Frame, placeholder: str = "") -> ttk.Entry:
        """创建现代风格输入框
        
        Args:
            parent: 父级Frame
            placeholder: 占位提示文字
            
        Returns:
            ttk.Entry输入框部件
        """
        container = tk.Frame(parent, bg=self.colors["background"])
        container.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        entry = ttk.Entry(
            container,
            style='Modern.TEntry',
            font=self.fonts["body"]
        )
        entry.pack(fill=tk.X, expand=True)
        
        # 实现占位文字功能
        if placeholder:
            entry.insert(0, placeholder)
            entry.config(foreground=self.colors["text_secondary"])
            
            def on_focus_in(event):
                if entry.get() == placeholder:
                    entry.delete(0, tk.END)
                    entry.config(foreground=self.colors["text_primary"])
            
            def on_focus_out(event):
                if not entry.get():
                    entry.insert(0, placeholder)
                    entry.config(foreground=self.colors["text_secondary"])
            
            entry.bind("<FocusIn>", on_focus_in)
            entry.bind("<FocusOut>", on_focus_out)
        
        return entry



    def _create_footer(self) -> None:
        """创建底部信息"""
        footer_frame = tk.Frame(self.root, bg=self.colors["background"], height=36)
        footer_frame.pack(fill=tk.X, padx=32, pady=(8, 12))

        footer_label = tk.Label(
            footer_frame,
            text="支持2GB+大文件 | 自动去重 | 路径安全保护",
            font=self.fonts["small"],
            fg=self.colors["text_secondary"],
            bg=self.colors["background"]
        )
        footer_label.pack(anchor="e")

    def _update_progress(self, current: int, total: int, percent: int) -> None:
        """更新进度显示"""
        self.progress_fill.pack_forget()

        # 重新创建进度条
        self.progress_fill = tk.Frame(self.progress_bg, bg=self.colors["accent"], height=6)
        self.progress_fill.pack(fill=tk.X, side=tk.LEFT)
        
        # 设置进度条宽度
        self.progress_fill.config(width=int(self.progress_bg.winfo_width() * percent / 100))

        self.progress_label.config(text=f"正在提取: {current}/{total} 页 ({percent}%)")

    def _hide_progress(self) -> None:
        """隐藏进度条"""
        self.progress_fill.pack_forget()
        self.progress_label.config(text="")

    def select_input_pdf(self) -> None:
        """选择输入PDF文件"""
        file_path = filedialog.askopenfilename(
            title="选择PDF文件",
            filetypes=[("PDF文档", "*.pdf"), ("全部文件", "*.*")]
        )

        if not file_path:
            return

        # 验证文件路径
        is_valid, error_msg = ValidationUtils.validate_file_path(file_path)
        if not is_valid:
            self._show_error(error_msg)
            return

        # 更新输入框
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, file_path)

        # 获取PDF信息
        try:
            page_count, size_mb = self.processor.get_pdf_info(file_path)
            self.total_pages = page_count
            self.current_file_size = size_mb

            # 显示文件信息
            size_str = f"{size_mb:.1f}MB" if size_mb >= 1 else f"{size_mb*1024:.0f}KB"
            self.info_label.config(
                text=f"文件信息: 共 {page_count} 页 | 大小 {size_str}",
                fg=self.colors["accent"]
            )

        except Exception as e:
            self.info_label.config(text="", fg=self.colors["text_secondary"])

        # 清除输出路径的默认建议
        self.output_entry.delete(0, tk.END)

    def select_output_pdf(self) -> None:
        """选择输出PDF文件"""
        input_path = self.input_entry.get().strip()
        default_name = ""

        if input_path:
            is_valid, _ = ValidationUtils.validate_file_path(input_path)
            if is_valid:
                base_name = PathSecurity.sanitize_filename(
                    os.path.splitext(os.path.basename(input_path))[0]
                )
                default_name = f"{base_name}_extracted.pdf"

        file_path = filedialog.asksaveasfilename(
            title="保存PDF文件",
            defaultextension=".pdf",
            initialfile=default_name,
            filetypes=[("PDF文档", "*.pdf"), ("全部文件", "*.*")]
        )

        if file_path:
            # 验证输出路径
            is_valid, error_msg = ValidationUtils.validate_output_path(file_path)
            if not is_valid:
                self._show_error(error_msg)
                return

            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, file_path)

    def extract_pages(self) -> None:
        """提取指定页码范围的PDF页面"""
        input_path = self.input_entry.get().strip()
        output_path = self.output_entry.get().strip()
        pages_text = self.pages_entry.get().strip()

        # 验证输入文件
        if not input_path:
            self._show_error("请选择源PDF文件")
            return

        is_valid, error_msg = ValidationUtils.validate_file_path(input_path)
        if not is_valid:
            self._show_error(error_msg)
            return

        # 验证输出路径
        if not output_path:
            self._show_error("请选择保存位置")
            return

        is_valid, error_msg = ValidationUtils.validate_output_path(output_path)
        if not is_valid:
            self._show_error(error_msg)
            return

        # 验证页码范围
        if not pages_text:
            self._show_error("请输入页码范围")
            return

        if self.total_pages == 0:
            self._show_error("无法读取PDF文件信息")
            return

        is_valid, valid_pages, page_error = ValidationUtils.validate_page_range(
            pages_text, self.total_pages
        )

        if not is_valid:
            self._show_error(page_error)
            return

        # 禁用按钮防止重复点击
        self.extract_button.config(state=tk.DISABLED, text="处理中...")

        try:
            # 执行提取
            extracted_count, invalid_count, invalid_pages = self.processor.extract_pages(
                input_path,
                output_path,
                valid_pages,
                progress_callback=self._update_progress
            )

            # 构建成功消息
            if page_error:
                success_msg = f"已提取 {extracted_count} 页{page_error}"
            else:
                success_msg = f"已成功提取 {extracted_count} 页"

            if invalid_count > 0:
                success_msg += f"\n另有 {invalid_count} 页超出范围"

            self._hide_progress()
            self._show_success(success_msg)

            # 清空输入
            self.input_entry.delete(0, tk.END)
            self.output_entry.delete(0, tk.END)
            self.pages_entry.delete(0, tk.END)
            self.info_label.config(text="")
            self.total_pages = 0

        except MemoryError as e:
            self._hide_progress()
            self._show_error(str(e))
        except Exception as e:
            self._hide_progress()
            self._show_error(f"处理失败: {str(e)}")
        finally:
            # 恢复按钮
            self.extract_button.config(state=tk.NORMAL, text="开始提取")

    def _show_error(self, message: str) -> None:
        """显示错误消息"""
        messagebox.showerror("错误", message)

    def _show_success(self, message: str) -> None:
        """显示成功消息"""
        messagebox.showinfo("完成", message)


def main() -> None:
    """主函数"""
    root = tk.Tk()
    app = PDFExtractorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()