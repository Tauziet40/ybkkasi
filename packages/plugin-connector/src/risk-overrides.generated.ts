/**
 * Constantes de couverture du catalogue de risques des connecteurs (déclaratifisation R6 — absorbe le modèle de catalogue déclaratif de paperclip app-definitions).
 *
 * ⚠️ Ce fichier est généré automatiquement par scripts/gen-connector-catalog.mjs, ne pas modifier à la main —
 *    source de fait : packages/plugin-connector/catalog/risk-overrides.json
 *    régénération : node scripts/gen-connector-catalog.mjs
 *
 * Priorité (resolveRiskLevel) : riskLevel porté par l'action > déclaration actions du présent catalogue >
 * defaultRisk du provider > heuristique heuristicRiskLevel en dernier recours (fail-closed, admin par défaut).
 * riskTier (S1/S2) sert uniquement de déclaration et d'affichage dans cette itération, couplage approbation à venir.
 */
import type { RiskOverrides } from './risk.ts'

export const RISK_OVERRIDES: RiskOverrides = {
  "dingtalk": {
    "actions": {
      "dingtalk.create_todo": "write",
      "dingtalk.delete_user": "admin",
      "dingtalk.get_user_info": "read",
      "dingtalk.list_departments": "read",
      "dingtalk.list_todos": "read",
      "dingtalk.send_work_message": "write"
    },
    "defaultRisk": "write",
    "riskTier": "S2"
  },
  "github": {
    "actions": {
      "github.create_issue": "write",
      "github.create_pull_request": "write",
      "github.delete_webhook": "admin",
      "github.list_issues": "read",
      "github.list_repositories": "read",
      "github.merge_pull_request": "write"
    },
    "defaultRisk": "write",
    "riskTier": "S2"
  },
  "gitlab": {
    "actions": {
      "gitlab.create_branch": "write",
      "gitlab.create_issue": "write",
      "gitlab.delete_project": "admin",
      "gitlab.list_issues": "read",
      "gitlab.list_projects": "read"
    },
    "defaultRisk": "write",
    "riskTier": "S2"
  },
  "google": {
    "actions": {
      "google.delete_file": "admin",
      "google.get_calendar_events": "read",
      "google.list_drive_files": "read",
      "google.send_gmail": "write",
      "google.share_file": "admin",
      "google.upload_file": "write"
    },
    "defaultRisk": "write",
    "riskTier": "S2"
  },
  "hackernews": {
    "actions": {
      "hackernews.do_the_thing": "admin",
      "hackernews.fetch_item": "read",
      "hackernews.get_top_stories": "read",
      "hackernews.submit_post": "write"
    },
    "defaultRisk": "read",
    "riskTier": "S1"
  },
  "jira": {
    "actions": {
      "jira.create_issue": "write",
      "jira.delete_issue": "admin",
      "jira.get_issue": "read",
      "jira.search_issues": "read",
      "jira.update_issue": "write"
    },
    "defaultRisk": "write",
    "riskTier": "S1"
  },
  "notion": {
    "actions": {
      "notion.create_page": "write",
      "notion.delete_page": "admin",
      "notion.get_page": "read",
      "notion.search_pages": "read",
      "notion.update_page": "write"
    },
    "defaultRisk": "write",
    "riskTier": "S1"
  },
  "slack": {
    "actions": {
      "slack.create_channel": "write",
      "slack.delete_channel": "admin",
      "slack.invite_user": "admin",
      "slack.list_channels": "read",
      "slack.search_messages": "read",
      "slack.send_message": "write"
    },
    "defaultRisk": "write",
    "riskTier": "S1"
  }
}
