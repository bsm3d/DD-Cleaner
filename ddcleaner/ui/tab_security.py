"""Security tab: audit, hardening profiles, advanced tweaks, telemetry."""

import json
import os
import subprocess
import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Tuple, Set

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QPushButton, QLabel, QTreeWidget, QTreeWidgetItem,
    QGroupBox, QGridLayout, QMessageBox, QDialog, QTextEdit, QComboBox, QListWidget,
    QScrollArea, QCheckBox, QRadioButton, QFrame
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor

from security_audit import SecurityDomain, RiskLevel, HardeningProfile, get_backup_dir, profile_action_count
from ddcleaner.common import SUBPROCESS_FLAGS, SYSTEM32, safe_environment, sys_exe
from ddcleaner import tweaks as tweaks_mod
from ddcleaner.system_utils import SystemUtils
from ddcleaner.workers import SecurityAuditWorker, HardeningApplyWorker, HardeningRevertWorker
from ddcleaner.ui.safe_text import plain, count
from ddcleaner.ui.tab_system_info import primary

SCORE_PENDING = "Score: -- / 100"


class SecurityTabMixin:
    """Security tab: audit, hardening profiles, advanced tweaks, telemetry. Mixed into MainWindow."""

    def _create_security_tab(self):
        """Create the single Security tab: audit, hardening profiles and advanced tweaks."""
        security_widget = QWidget()
        outer_layout = QVBoxLayout(security_widget)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer_layout.addWidget(scroll)
        content = QWidget()
        scroll.setWidget(content)
        layout = QVBoxLayout(content)

        # Title
        title_label = QLabel("🛡️ Security: audit, hardening profiles and advanced tweaks")
        title_label.setStyleSheet("font-weight: bold; font-size: 16px; padding: 10px;")
        layout.addWidget(title_label)

        # Score display (top)
        score_group = QGroupBox("Overall security score")
        score_layout = QVBoxLayout()

        self.security_score_label = QLabel(SCORE_PENDING)
        self.security_score_label.setStyleSheet("font-size: 36px; font-weight: bold; color: gray;")
        self.security_score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        score_layout.addWidget(self.security_score_label)

        self.security_status_label = QLabel("No audit yet")
        self.security_status_label.setStyleSheet("font-size: 14px; color: gray; font-style: italic;")
        self.security_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        score_layout.addWidget(self.security_status_label)

        score_group.setLayout(score_layout)
        layout.addWidget(score_group)

        # Action buttons
        btn_layout = QHBoxLayout()

        self.security_audit_btn = primary(QPushButton("🔍 Run full audit"))
        self.security_audit_btn.clicked.connect(self._start_security_audit)
        # no colour here: the application style already greys a disabled button, an inline colour would hide that
        self.security_audit_btn.setStyleSheet("font-size: 14px; padding: 10px;")

        self.security_apply_profile_btn = QPushButton("🛡️ Apply hardening profile...")
        self.security_apply_profile_btn.clicked.connect(self._show_hardening_profiles)
        self.security_apply_profile_btn.setEnabled(False)
        self.security_apply_profile_btn.setToolTip("Run an audit first: a profile is applied to what the audit found.")
        self.security_apply_profile_btn.setStyleSheet("font-size: 14px; padding: 10px;")

        self.security_details_btn = QPushButton("📋 View details")
        self.security_details_btn.clicked.connect(self._show_security_details)
        self.security_details_btn.setEnabled(False)
        self.security_details_btn.setToolTip("Run an audit first.")

        self.security_revert_btn = QPushButton("↩️ Undo a change...")
        self.security_revert_btn.setToolTip(
            "Restores the exact state saved before a profile or advanced tweaks were applied (most recent by default)")
        self.security_revert_btn.clicked.connect(self._revert_security_change)

        btn_layout.addWidget(self.security_audit_btn)
        btn_layout.addWidget(self.security_apply_profile_btn)
        btn_layout.addWidget(self.security_details_btn)
        btn_layout.addWidget(self.security_revert_btn)
        layout.addLayout(btn_layout)

        # Domain scores
        domains_group = QGroupBox("Scores by domain")
        domains_layout = QGridLayout()

        self.domain_labels = {}
        domains = [
            (SecurityDomain.SYSTEM, "🖥️ System", 0, 0),
            (SecurityDomain.ACCOUNTS, "👤 Accounts", 0, 1),
            (SecurityDomain.NETWORK, "🌐 Network", 1, 0),
            (SecurityDomain.DATA, "💾 Data", 1, 1)
        ]

        for domain, label_text, row, col in domains:
            domain_widget = QFrame()
            domain_widget.setObjectName("domainCard")
            domain_layout = QVBoxLayout(domain_widget)
            domain_layout.setContentsMargins(10, 10, 10, 10)

            name_label = QLabel(label_text)
            name_label.setStyleSheet("font-weight: bold; font-size: 12px;")
            domain_layout.addWidget(name_label)

            score_label = QLabel("-- / 25")
            score_label.setStyleSheet("font-size: 24px; color: gray;")
            score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            domain_layout.addWidget(score_label)

            status_label = QLabel("Not audited")
            status_label.setStyleSheet("font-size: 11px; color: gray;")
            status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            domain_layout.addWidget(status_label)

            # by name: a plain "QWidget { border }" rule would also frame each of the three labels inside
            domain_widget.setStyleSheet("#domainCard { border: 1px solid #ccc; border-radius: 5px; background-color: #f9f9f9; }")
            domains_layout.addWidget(domain_widget, row, col)

            self.domain_labels[domain] = (score_label, status_label)

        domains_group.setLayout(domains_layout)
        layout.addWidget(domains_group)

        # Critical issues
        issues_group = QGroupBox("🔴 Top 5 critical issues")
        issues_layout = QVBoxLayout()

        self.security_issues_list = QListWidget()
        self.security_issues_list.setMaximumHeight(150)
        issues_layout.addWidget(self.security_issues_list)

        issues_group.setLayout(issues_layout)
        layout.addWidget(issues_group)

        layout.addWidget(self._build_advanced_tweaks_group())

        layout.addStretch()

        self.tab_widget.addTab(security_widget, "🛡️ Security")

        # Load default tweak set
        self._load_hardening_profile("Safe (Recommended)", announce=False)

    def _build_advanced_tweaks_group(self) -> QGroupBox:
        """Advanced tweaks section (services, WSH, script associations, telemetry scan)."""
        group = QGroupBox("🔒 Advanced tweaks (services, scripts, telemetry)")
        layout = QVBoxLayout(group)

        # Preset selector
        title_layout = QHBoxLayout()
        title_layout.addStretch()

        profile_label = QLabel("Tweak set:")
        self.hardening_profile = QComboBox()
        self.hardening_profile.addItems(["Safe (Recommended)", "Medium", "Aggressive", "Custom"])
        self.hardening_profile.currentTextChanged.connect(self._load_hardening_profile)
        title_layout.addWidget(profile_label)
        title_layout.addWidget(self.hardening_profile)
        layout.addLayout(title_layout)

        # Info label
        info_label = QLabel("⚠️ The current state is saved before every change (undo with "
                            "\"Undo a change\"). Administrator rights required. These tweak sets are separate from "
                            "the hardening profiles above.")
        info_label.setWordWrap(True)
        info_label.setStyleSheet("color: #b35900; font-style: italic;")
        layout.addWidget(info_label)

        # Tweaks list (QTreeWidget with checkboxes)
        self.hardening_tree = QTreeWidget()
        self.hardening_tree.setHeaderLabels(["✓", "Category", "Tweak", "Description", "Risk"])
        self.hardening_tree.setColumnWidth(0, 30)
        self.hardening_tree.setColumnWidth(1, 120)
        self.hardening_tree.setColumnWidth(2, 200)
        self.hardening_tree.setColumnWidth(3, 300)
        self.hardening_tree.setColumnWidth(4, 80)
        self.hardening_tree.setMinimumHeight(180)
        layout.addWidget(self.hardening_tree)

        self.open_scripts_in_editor_cb = QCheckBox("Open blocked scripts in Notepad instead of removing their association")
        self.open_scripts_in_editor_cb.setToolTip(
            "A double click on a .js/.vbs/.vbe/.jse/.wsf/.hta file shows its text in Notepad "
            "(it is never run). Undo restores the previous association.")
        layout.addWidget(self.open_scripts_in_editor_cb)

        # Buttons (revert is the shared "Undo a change" button above)
        btn_layout = QHBoxLayout()
        self.apply_hardening_btn = QPushButton("✅ Apply ticked tweaks...")
        self.scan_telemetry_btn = QPushButton("📊 Scan telemetry (30 s)...")

        self.apply_hardening_btn.clicked.connect(self._apply_hardening)
        self.scan_telemetry_btn.clicked.connect(self._scan_telemetry)

        btn_layout.addWidget(self.apply_hardening_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.scan_telemetry_btn)
        layout.addLayout(btn_layout)

        # Output zone
        output_label = QLabel("Output:")
        output_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(output_label)

        self.hardening_output = QTextEdit()
        self.hardening_output.setReadOnly(True)
        self.hardening_output.setMaximumHeight(150)
        self.hardening_output.setPlaceholderText("Details of applied or reverted tweaks appear here...")
        self.hardening_output.setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; font-size: 10pt;")
        layout.addWidget(self.hardening_output)

        return group

    def _start_security_audit(self):
        """Start comprehensive security audit."""
        running = getattr(self, "security_audit_worker", None)
        if running is not None and running.isRunning():
            return
        self.security_audit_btn.setEnabled(False)
        self.security_apply_profile_btn.setEnabled(False)
        self.security_details_btn.setEnabled(False)
        self.security_status_label.setText("⏳ Audit in progress...")
        self.progress_bar.setVisible(True)
        self._update_status("Running security audit...")

        # Run audit in separate thread
        audit_worker = SecurityAuditWorker(self.security_auditor)
        audit_worker.finished.connect(self._on_security_audit_complete)
        audit_worker.progress.connect(self._update_status)
        audit_worker.start()

        # Store worker to prevent garbage collection
        self.security_audit_worker = audit_worker

    def _on_security_audit_complete(self, global_score: int, domain_scores: dict):
        """Handle security audit completion."""
        self.progress_bar.setVisible(False)
        self.security_audit_btn.setEnabled(True)
        error = getattr(getattr(self, "security_audit_worker", None), "error", "")
        if error:
            # a failed audit has no score: showing "0 / 100, Critical" would be a false alarm
            self.last_audit_score, self.last_audit_domains = 0, {}
            self.security_score_label.setText(SCORE_PENDING)
            self.security_score_label.setStyleSheet("font-size: 36px; font-weight: bold; color: gray;")
            self.security_status_label.setText(plain(f"The audit failed: {error}"))
            self.security_status_label.setStyleSheet("font-size: 14px; color: #dc3545; font-weight: bold;")
            self._update_status("Security audit failed.")
            return
        self.security_apply_profile_btn.setEnabled(True)
        self.security_details_btn.setEnabled(True)

        self.last_audit_score = global_score
        self.last_audit_domains = dict(domain_scores)  # own copy: next audit must not mutate it

        # Update global score
        score_color = self._get_score_color(global_score)
        self.security_score_label.setText(f"Score: {global_score} / 100")
        self.security_score_label.setStyleSheet(f"font-size: 36px; font-weight: bold; color: {score_color};")

        # Status text
        if global_score >= 85:
            status = "🟢 Excellent - Well secured"
        elif global_score >= 70:
            status = "🟡 Fair - Some improvements recommended"
        elif global_score >= 50:
            status = "🟠 Medium - Several security issues found"
        else:
            status = "🔴 Critical - Vulnerable, act now"

        self.security_status_label.setText(status)
        self.security_status_label.setStyleSheet(f"font-size: 14px; color: {score_color}; font-weight: bold;")

        # Update domain scores (each domain's own maximum: it is not the same as its weight in the global score)
        for domain, (score_label, status_label) in self.domain_labels.items():
            if domain in domain_scores:
                domain_score_obj = domain_scores[domain]
                score = domain_score_obj.current_score
                max_score = domain_score_obj.max_score
                percentage = domain_score_obj.percentage

                score_label.setText(f"{score} / {max_score}")
                score_label.setStyleSheet(f"font-size: 24px; color: {self._get_score_color(percentage)};")
                status_label.setText(domain_score_obj.status)
                status_label.setStyleSheet(f"font-size: 11px; color: {self._get_score_color(percentage)};")

        # Update critical issues
        self.security_issues_list.clear()
        critical_issues = self.security_auditor.get_critical_issues(limit=5)

        for issue in critical_issues:
            risk_emoji = {
                RiskLevel.CRITICAL: "🔴",
                RiskLevel.HIGH: "🟠",
                RiskLevel.MEDIUM: "🟡",
                RiskLevel.LOW: "🟢"
            }.get(issue.risk, "⚪")

            item_text = f"{risk_emoji} {issue.title} ({issue.domain.value})"
            self.security_issues_list.addItem(item_text)

        if not critical_issues:
            self.security_issues_list.addItem("✅ No critical issue")

        self._update_status(f"Security audit completed. Score: {global_score}/100")
        logging.info(f"Security audit completed. Global score: {global_score}/100")

    def _get_score_color(self, score: float) -> str:
        """Get color based on score percentage."""
        if score >= 85:
            return "#28a745"  # Green
        elif score >= 70:
            return "#b38600"  # Dark yellow (readable as text on a light background)
        elif score >= 50:
            return "#fd7e14"  # Orange
        else:
            return "#dc3545"  # Red

    def _show_security_details(self):
        """Show detailed security audit results."""
        if not self.last_audit_domains:
            QMessageBox.information(self, "Details", "No audit available. Run an audit first.")
            return

        details_dialog = QDialog(self)
        details_dialog.setWindowTitle("Security Audit Details")
        details_dialog.resize(1000, 700)

        layout = QVBoxLayout(details_dialog)

        # Summary
        summary_label = QLabel(f"📊 Overall score: {self.last_audit_score}/100")
        summary_label.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(summary_label)

        # Tabs for domains
        domain_tabs = QTabWidget()

        for domain in SecurityDomain:
            if domain in self.last_audit_domains:
                domain_score = self.last_audit_domains[domain]
                domain_widget = self._create_domain_detail_widget(domain_score)
                domain_tabs.addTab(domain_widget, f"{domain.value} ({domain_score.current_score}/{domain_score.max_score})")

        layout.addWidget(domain_tabs)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(details_dialog.close)
        layout.addWidget(close_btn)
        self._set_dialog_default(details_dialog, close_btn)

        details_dialog.exec()
        details_dialog.deleteLater()

    def _create_domain_detail_widget(self, domain_score) -> QWidget:
        """Create widget showing domain issues details."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Domain summary
        summary = QLabel(f"{domain_score.status} - {len(domain_score.issues)} issue(s) found")
        summary.setStyleSheet("font-weight: bold; font-size: 12px; padding: 5px;")
        layout.addWidget(summary)

        # Issues tree
        issues_tree = QTreeWidget()
        issues_tree.setHeaderLabels(["Issue", "Risk", "Current state", "Recommended action"])
        issues_tree.setColumnWidth(0, 300)
        issues_tree.setColumnWidth(1, 80)
        issues_tree.setColumnWidth(2, 150)

        for issue in domain_score.issues:
            item = QTreeWidgetItem()
            item.setText(0, issue.title)
            item.setText(1, issue.risk.value)
            item.setText(2, issue.current_state)
            item.setText(3, issue.recommended_action)

            # Color code by risk
            if issue.risk == RiskLevel.CRITICAL:
                item.setForeground(1, QColor("#dc3545"))
            elif issue.risk == RiskLevel.HIGH:
                item.setForeground(1, QColor("#fd7e14"))
            elif issue.risk == RiskLevel.MEDIUM:
                item.setForeground(1, QColor("#b38600"))

            # Tooltip with full description
            item.setToolTip(0, plain(issue.description))

            issues_tree.addTopLevelItem(item)

        if not domain_score.issues:
            no_issues = QTreeWidgetItem()
            no_issues.setText(0, "✅ No issue found in this domain")
            no_issues.setForeground(0, QColor("#28a745"))
            issues_tree.addTopLevelItem(no_issues)

        layout.addWidget(issues_tree)

        return widget

    def _show_hardening_profiles(self):
        """Show hardening profiles dialog."""
        profile_dialog = QDialog(self)
        profile_dialog.setWindowTitle("🛡️ Hardening profiles")
        profile_dialog.resize(800, 520)

        layout = QVBoxLayout(profile_dialog)

        info_label = QLabel(
            "Choose a hardening profile to apply.\n"
            "The current state is saved first (undo with \"Undo a change\") and a restore point is attempted."
        )
        info_label.setStyleSheet("font-style: italic; color: gray; padding: 10px;")
        layout.addWidget(info_label)

        profile_group = QGroupBox("Available profiles")
        profile_layout = QVBoxLayout()
        descriptions = {
            HardeningProfile.BASIC: "Defender, firewall, Guest account, auto-logon\nLow impact • Reversible",
            HardeningProfile.RECOMMENDED: "Basic + anonymous SAM access restriction, built-in Administrator disabled "
                                          "(with safety checks), WDigest clear-text passwords off, SMBv1 server off\n"
                                          "Medium impact • Reversible",
            HardeningProfile.STRICT: "Recommended + RDP off, NTLMv2 only, UAC max, Remote Registry off, NetBIOS over "
                                     "TCP/IP off\nHigh impact (may break RDP / old NAS / workgroup browsing) • Reversible",
        }
        self.selected_hardening_profile = HardeningProfile.RECOMMENDED
        for profile, description in descriptions.items():
            radio = QRadioButton(self._profile_label(profile))
            radio.setStyleSheet("font-weight: bold; padding: 6px;" if profile == HardeningProfile.RECOMMENDED
                                else "padding: 6px;")
            radio.setChecked(profile == self.selected_hardening_profile)
            radio.toggled.connect(lambda on, chosen=profile: on and self._select_profile(chosen))
            detail = QLabel(description)
            detail.setWordWrap(True)
            detail.setStyleSheet("font-size: 12px; color: gray; padding-left: 30px;")
            profile_layout.addWidget(radio)
            profile_layout.addWidget(detail)
        profile_group.setLayout(profile_layout)
        layout.addWidget(profile_group)
        layout.addStretch()

        btn_layout = QHBoxLayout()
        apply_btn = QPushButton("✅ Apply profile...")
        apply_btn.clicked.connect(lambda: self._apply_hardening_profile(profile_dialog))
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(profile_dialog.close)
        btn_layout.addStretch()
        btn_layout.addWidget(apply_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        self._set_dialog_default(profile_dialog, apply_btn)  # Enter applies (after a confirmation), it changes no choice

        profile_dialog.exec()
        profile_dialog.deleteLater()

    def _select_profile(self, profile: HardeningProfile):
        self.selected_hardening_profile = profile

    @staticmethod
    def _profile_label(profile: HardeningProfile) -> str:
        """'Recommended (8 actions) ⭐': the action count comes from the profile definition."""
        star = " ⭐" if profile == HardeningProfile.RECOMMENDED else ""
        return f"{profile.value} ({profile_action_count(profile)} actions){star}"

    def _apply_hardening_profile(self, dialog: QDialog):
        """Apply selected hardening profile."""
        if not SystemUtils.check_admin_privileges():
            QMessageBox.warning(self, "Administrator Required",
                                "Applying a hardening profile needs administrator rights.\n"
                                "Restart the application as administrator.")
            return
        if not self._confirm("Apply hardening profile",
                             f"Apply the {self.selected_hardening_profile.value} profile?\n\n"
                             "The current state is saved first and a restore point is attempted.\n"
                             "Undo with \"Undo a change\"."):
            return

        worker = getattr(self, "hardening_apply_worker", None)
        if worker is not None and worker.isRunning():
            QMessageBox.information(self, "Info", "Hardening is already running.")
            return
        audit = getattr(self, "security_audit_worker", None)
        if audit is not None and audit.isRunning():
            QMessageBox.information(self, "Info", "Wait for the running audit to finish.")
            return

        dialog.close()

        # Restore point + profile run in a worker thread (can take minutes)
        self._update_status(f"Applying {self.selected_hardening_profile.value} profile (restore point first)...")
        self.progress_bar.setVisible(True)
        self.security_apply_profile_btn.setEnabled(False)
        self.hardening_apply_worker = HardeningApplyWorker(self.hardening_engine, self.selected_hardening_profile)
        self.hardening_apply_worker.progress.connect(self._update_status)
        self.hardening_apply_worker.done.connect(self._on_hardening_profile_applied)
        self.hardening_apply_worker.start()

    def _on_hardening_profile_applied(self, success: int, failures: int, errors: list, restore_point_ok: bool):
        """GUI-thread completion of HardeningApplyWorker."""
        self.progress_bar.setVisible(False)
        self.security_apply_profile_btn.setEnabled(True)

        # Show results
        result_msg = "Hardening completed:\n\n"
        rp_message = getattr(self.hardening_engine, "last_restore_point_message", "")
        result_msg += ("✅ Restore point created\n" if restore_point_ok else
                       f"⚠️ Restore point not created. {rp_message}\n")
        backup_path = getattr(self.hardening_engine, "last_backup_path", None)
        if backup_path:
            result_msg += f"💾 State saved to: {backup_path}\n"
        skipped = getattr(self.hardening_engine, "last_skipped", [])
        if skipped:
            result_msg += "⏭️ Skipped (safety):\n  " + "\n  ".join(skipped[:5]) + "\n"
        result_msg += f"✅ {success} action(s) applied successfully\n"
        if failures > 0:
            result_msg += f"❌ {failures} failure(s)\n\n"
            result_msg += "Errors:\n" + "\n".join(errors[:5])
            if len(errors) > 5:
                result_msg += f"\n... and {len(errors) - 5} more (see the log)"

        QMessageBox.information(self, "Hardening completed", result_msg)

        # Re-run audit
        self._start_security_audit()

    def _revert_security_change(self):
        """
        Single revert entry point for the Security tab.
        hardening_backup_*.json -> HardeningEngine (profiles); tweaks_backup_*.json -> advanced tweaks.
        """
        if not SystemUtils.check_admin_privileges():
            QMessageBox.warning(self, "Administrator Required", "Undoing changes requires administrator rights.")
            return
        for attr in ("hardening_apply_worker", "hardening_revert_worker", "security_audit_worker"):
            w = getattr(self, attr, None)
            if w is not None and w.isRunning():
                QMessageBox.information(self, "Info", "A security operation is already running.")
                return
        running = self._bg_threads.get("hardening")
        if running and running.is_alive():
            QMessageBox.information(self, "Info", "Advanced tweaks are being applied.")
            return

        folder = get_backup_dir()
        backups = sorted(
            (os.path.join(folder, f) for f in os.listdir(folder)
             if f.endswith(".json") and f.startswith(("hardening_backup_", "tweaks_backup_"))),
            key=os.path.getmtime, reverse=True
        ) if os.path.isdir(folder) else []

        if not backups:
            if self._confirm("No backup", "No backup found.\n\nReset the advanced tweaks (services, Windows Script "
                                          "Host, script file associations) to Windows 10 defaults?"):
                self._run_hardening_commands(list(tweaks_mod.WIN10_DEFAULT_RESTORE), snapshot=True)
            return

        backup_file = self._choose_backup(backups)
        if not backup_file:
            return
        name = os.path.basename(backup_file)
        if os.path.normcase(os.path.dirname(os.path.abspath(backup_file))) != os.path.normcase(folder):
            QMessageBox.warning(self, "Refused", f"Only backups from\n{folder}\nare accepted.")
            return

        if name.startswith("tweaks_backup_"):
            try:
                commands = tweaks_mod.revert_commands_from_snapshot(backup_file)
            except (OSError, ValueError, KeyError) as e:
                QMessageBox.critical(self, "Error", plain(f"Invalid backup: {e}"))
                return
            if self._confirm("Undo advanced tweaks",
                             f"Restore {count(len(commands), 'setting')} to the state saved in:\n{backup_file}?"):
                # Snapshot again first, so the revert itself can be undone
                self._run_hardening_commands(commands, snapshot=True)
            return

        if not name.startswith("hardening_backup_"):
            QMessageBox.warning(self, "Refused", "Unrecognized backup file.")
            return
        if not self._confirm("Undo hardening profile", f"Restore the state saved in:\n{backup_file}?"):
            return
        self.security_revert_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.hardening_revert_worker = HardeningRevertWorker(self.hardening_engine, backup_file)
        self.hardening_revert_worker.progress.connect(self._update_status)
        self.hardening_revert_worker.done.connect(self._on_hardening_reverted)
        self.hardening_revert_worker.start()

    def _choose_backup(self, backups: List[str]) -> str:
        """The saved states, most recent first, with what each one undoes. Returns the chosen file or ''."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Undo a change")
        dialog.resize(820, 360)
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Choose the change to undo: the state saved just before it is restored."))
        tree = QTreeWidget()
        tree.setHeaderLabels(["Saved on", "Change", "Settings", "File"])
        tree.setRootIsDecorated(False)
        for column, width in enumerate((140, 250, 70)):
            tree.setColumnWidth(column, width)
        for path in backups:
            kind, settings = self._describe_backup(path)
            item = QTreeWidgetItem([datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M"), kind,
                                    settings, os.path.basename(path)])
            item.setData(0, Qt.ItemDataRole.UserRole, path)
            tree.addTopLevelItem(item)
        tree.setCurrentItem(tree.topLevelItem(0))
        tree.itemDoubleClicked.connect(lambda *_: dialog.accept())
        layout.addWidget(tree)
        row = QHBoxLayout()
        undo_btn = QPushButton("↩️ Undo this change...")
        undo_btn.clicked.connect(dialog.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        row.addStretch()
        row.addWidget(undo_btn)
        row.addWidget(cancel_btn)
        layout.addLayout(row)
        self._set_dialog_default(dialog, cancel_btn)
        accepted = dialog.exec() == QDialog.DialogCode.Accepted
        chosen = tree.currentItem().data(0, Qt.ItemDataRole.UserRole) if accepted and tree.currentItem() else ""
        dialog.deleteLater()
        return chosen

    @staticmethod
    def _describe_backup(path: str) -> Tuple[str, str]:
        """(what the backup undoes, how many settings it holds) for the list of _choose_backup."""
        try:
            if os.path.basename(path).startswith("tweaks_backup_"):
                return "Advanced tweaks", str(len(tweaks_mod.revert_commands_from_snapshot(path)))
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return f"Hardening profile: {data.get('profile', '?')}", str(len(data.get("entries", [])))
        except (OSError, ValueError, KeyError, AttributeError, TypeError):
            return "Unreadable backup", ""

    def _on_hardening_reverted(self, reverted: int, failed: int):
        self.progress_bar.setVisible(False)
        self.security_revert_btn.setEnabled(True)
        if failed < 0:
            QMessageBox.critical(self, "Error", "Undo failed (see logs).")
        else:
            QMessageBox.information(self, "Undo completed",
                                    f"✅ {reverted} setting(s) restored\n❌ {failed} failure(s)")
        self._start_security_audit()

    def _load_hardening_profile(self, profile_name: str, announce: bool = True):
        """Load a tweak set and populate the tree. announce: say so in the output (not at startup, where the
        output still shows its placeholder)."""
        self.hardening_tree.clear()

        # Get selected profile tweaks
        tweaks = tweaks_mod.PRESETS.get(profile_name, [])

        # Populate tree
        for category, name, command, description, risk in tweaks:
            item = QTreeWidgetItem()
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            # Check all by default for non-Custom profiles
            check_state = Qt.CheckState.Checked if profile_name != "Custom" else Qt.CheckState.Unchecked
            item.setCheckState(0, check_state)
            item.setText(1, category)
            item.setText(2, name)
            item.setText(3, description)
            item.setText(4, risk)
            # Store command in item data
            item.setData(0, Qt.ItemDataRole.UserRole, command)

            # Color code by risk
            if risk == "Low":
                item.setForeground(4, QColor("#28a745"))  # Green
            elif risk == "Medium":
                item.setForeground(4, QColor("#ff6600"))  # Orange
            elif risk == "High":
                item.setForeground(4, QColor("#dc3545"))  # Red

            self.hardening_tree.addTopLevelItem(item)

        if announce:
            self.hardening_output.append(f"Tweak set loaded: {profile_name} ({count(len(tweaks), 'tweak')})\n")

    def _apply_hardening(self):
        """Apply selected hardening tweaks."""
        # Check admin privileges
        if not SystemUtils.check_admin_privileges():
            QMessageBox.warning(
                self,
                "Administrator Required",
                "Hardening tweaks require administrator privileges.\n\nPlease restart the application as administrator."
            )
            return

        # Collect selected tweaks
        selected = []
        for i in range(self.hardening_tree.topLevelItemCount()):
            item = self.hardening_tree.topLevelItem(i)
            if item.checkState(0) == Qt.CheckState.Checked:
                name = item.text(2)
                cmd = item.data(0, Qt.ItemDataRole.UserRole)
                if self.open_scripts_in_editor_cb.isChecked():
                    cmd = tweaks_mod.open_in_editor(cmd)
                selected.append((name, cmd))

        if not selected:
            QMessageBox.information(self, "Info", "Tick the tweaks to apply first.")
            return

        if not self._confirm("Apply tweaks",
                             f"Apply {count(len(selected), 'tweak')}?\n\n"
                             "The current state is saved first and a restore point is attempted.\n"
                             "Some changes may require a reboot.\n"
                             "Undo with \"Undo a change\".\n\nContinue?"):
            return

        self._run_hardening_commands(selected)

    def _run_hardening_commands(self, tweaks: List[Tuple[str, str]], snapshot: bool = True):
        """Execute hardening commands in a background thread (state snapshot first)."""
        running = self._bg_threads.get("hardening")
        if running and running.is_alive():
            QMessageBox.information(self, "Info", "Hardening is already running.")
            return

        snapshot_file = None
        if snapshot:
            snapshot_file = tweaks_mod.snapshot_tweaks(tweaks, get_backup_dir())
            if not snapshot_file:
                QMessageBox.critical(self, "Hardening aborted",
                                     "Could not save the current state (hardening_backups).\nNothing was changed.")
                return

        self.progress_bar.setVisible(True)
        self.hardening_output.clear()
        self.hardening_output.append(f"=== Applying {len(tweaks)} tweaks ===\n")
        if snapshot_file:
            self.hardening_output.append(f"State saved to: {snapshot_file}\n")

        def emit(text: str):
            self._ui(lambda: self.hardening_output.append(text))

        def worker():
            """Worker thread: never touches widgets directly."""
            if snapshot:
                create_rp = getattr(self.hardening_engine, "create_restore_point", None)
                if callable(create_rp):
                    emit("Creating system restore point...\n")
                    try:
                        emit("✅ Restore point created\n" if create_rp() else
                             "⚠️ Restore point not created (System Protection off or already created in last 24h). "
                             "The JSON snapshot still allows revert.\n")
                    except Exception as e:
                        emit(f"⚠️ Restore point error: {e}\n")

            for name, cmd in tweaks:
                emit(f"\n> {name}\n$ {cmd}\n")
                try:
                    result = subprocess.run(
                        tweaks_mod.hardening_argv(cmd),
                        capture_output=True, text=True, shell=False, cwd=SYSTEM32, env=safe_environment(),
                        timeout=60, creationflags=SUBPROCESS_FLAGS
                    )
                    output = result.stdout or result.stderr or "Command completed"
                    emit(f"{output.strip()}\n")
                    emit("✅ Success\n" if result.returncode == 0 else f"⚠️ Exit code: {result.returncode}\n")
                except subprocess.TimeoutExpired:
                    emit("❌ ERROR: Command timeout (60s)\n")
                except Exception as e:
                    emit(f"❌ ERROR: {e}\n")

            def finish():
                self.hardening_output.append("\n=== Completed ===\n")
                self.hardening_output.append("ℹ️ Reboot recommended for all changes to take effect.\n")
                self.progress_bar.setVisible(False)
                self._update_status("Hardening tweaks applied. Reboot recommended.")
            self._ui(finish)

        self._start_bg_thread("hardening", worker)

    TELEMETRY_KEYWORDS = (
        "microsoft", "windows", "msft", "msn.", "live.com", "bing.", "office", "skype", "msedge",
        "azure", "xbox", "telemetry", "watson", "vortex", "events.data", "settings-win",
        "smartscreen", "wns.", "msftncsi", "aria.", "onedrive", "visualstudio", "trafficmanager.net",
    )

    # One locale-independent snapshot: established TCP connections, DNS cache, process names
    TELEMETRY_PS = (
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
        "$c = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
        "  Where-Object { $_.RemoteAddress -notmatch '^(127\\.|::1|0\\.0\\.0\\.0)' } | "
        "  Select-Object RemoteAddress, RemotePort, OwningProcess; "
        "$d = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Data } | Select-Object Entry, Data; "
        "$p = Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName; "
        "@{ conn = @($c); dns = @($d); proc = @($p) } | ConvertTo-Json -Depth 3 -Compress"
    )

    def _scan_telemetry(self):
        """Watch established connections for 30 s and report those going to Microsoft/telemetry hosts."""
        if not self._confirm("Telemetry scan",
                             "Watch network connections for 30 seconds?\n\n"
                             "Remote IP addresses are matched to host names using the DNS cache, "
                             "then filtered on Microsoft / Windows / Office / telemetry domains.\n\n"
                             "Nothing is blocked or modified. Continue?"):
            return

        # appended, not cleared: the result of the last tweaks stays readable above
        self.hardening_output.append("\n🔍 Watching connections (30 seconds)...\n")
        stopped = self._stopper("telemetry")
        self.progress_bar.setVisible(True)

        def emit(text: str):
            self._ui(lambda: self.hardening_output.append(text))

        def scan_worker():
            """Worker thread: sample connections every ~3 s, never touches widgets directly."""
            import json
            ip_names: Dict[str, Set[str]] = defaultdict(set)
            proc_names: Dict[int, str] = {}
            hits: Dict[int, Set[Tuple[str, str]]] = defaultdict(set)  # pid -> {(ip, host)}
            end_time = time.time() + 30
            samples = 0

            while time.time() < end_time and not stopped():
                samples += 1
                try:
                    completed = subprocess.run(
                        [sys_exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", self.TELEMETRY_PS],
                        capture_output=True, text=True, encoding="utf-8", errors="replace",
                        cwd=SYSTEM32, env=safe_environment(), timeout=20, creationflags=SUBPROCESS_FLAGS
                    )
                    data = json.loads(completed.stdout) if completed.stdout.strip() else {}
                except subprocess.TimeoutExpired:
                    emit("⚠️ Sample timed out, continuing...\n")
                    continue
                except (ValueError, OSError) as e:
                    emit(f"⚠️ Sample error: {e}\n")
                    time.sleep(3)
                    continue

                for rec in data.get("dns") or []:
                    if rec and rec.get("Data") and rec.get("Entry"):
                        ip_names[str(rec["Data"])].add(str(rec["Entry"]).lower())
                for rec in data.get("proc") or []:
                    if rec and rec.get("Id") is not None:
                        proc_names[int(rec["Id"])] = rec.get("ProcessName") or "?"
                for rec in data.get("conn") or []:
                    if not rec:
                        continue
                    ip = str(rec.get("RemoteAddress"))
                    for host in ip_names.get(ip, ()):
                        if any(k in host for k in self.TELEMETRY_KEYWORDS):
                            hits[int(rec.get("OwningProcess") or 0)].add((ip, host))
                time.sleep(3)

            lines = [f"\n📊 Results ({samples} samples):\n", "=" * 60 + "\n\n"]
            if not hits:
                lines.append("✅ No connection to Microsoft/telemetry hosts detected "
                             "(connections whose name is not in the DNS cache cannot be identified).\n")
            else:
                lines.append(f"{len(hits)} process(es) connected to Microsoft/telemetry hosts:\n\n")
                for pid, pairs in sorted(hits.items(), key=lambda kv: -len(kv[1])):
                    lines.append(f"🔸 {proc_names.get(pid, 'PID ' + str(pid))} (PID {pid}): {len(pairs)} connection(s)\n")
                    for ip, host in sorted(pairs)[:5]:
                        lines.append(f"   └─ {host} ({ip})\n")
                    if len(pairs) > 5:
                        lines.append(f"   └─ ... and {len(pairs) - 5} more\n")
                    lines.append("\n")
            emit("".join(lines))
            self._ui(lambda: self.progress_bar.setVisible(False))
            self._update_status("Telemetry scan completed.")

        if not self._start_bg_thread("telemetry", scan_worker):
            self.progress_bar.setVisible(False)
