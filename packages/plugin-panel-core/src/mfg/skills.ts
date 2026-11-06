/**
 * Boîte à outils manufacture — registre de Skills versionné (intégré depuis « jeu d'outils IA manufacture » server/skills.ts).
 *
 * Loi d'airain (docs/skill-quality.md du projet source, inchangée après intégration) : un Skill candidat n'entre pas dans l'entrée d'appel ordinaire
 * parce qu'il « s'installe, renvoie du texte, est bien classé au marché ». Ce registre n'enregistre que les noyaux de prompts rédigés par le projet — il ne charge ni n'exécute
 * aucun texte d'instruction uploadé (première frontière contre l'injection de prompt).
 */

export type Skill = {
  version: string
  origin: 'project-authored'
  license: string
  /** Séquence fixe de sections : la sortie du modèle doit les avoir toutes dans cet ordre ; manquante ou désordonnée = jugée non conforme. */
  sections: string[]
  instructions: string
}

export const skills: Record<string, Skill> = {
  'sop-writer': {
    version: '1.1.0',
    origin: 'project-authored',
    license: 'project-internal',
    sections: ['目的与范围', '准备条件', '操作步骤', '质量检查', '异常处理'],
    instructions: '你是制造业标准作业指导书编辑。只使用用户提供的技术参数。扭矩、温度、安全措施等缺失参数必须列为待工艺工程师确认。不得编造标准编号或声称已审批。步骤中的未知参数用待确认占位，禁止自行选择数值。',
  },
  'root-cause': {
    version: '1.1.0',
    origin: 'project-authored',
    license: 'project-internal',
    sections: ['已知事实', '原因假设', '验证计划', '临时遏制', '长期改善'],
    instructions: '你是制造业质量改善助手。使用5 Why形成可证伪假设。严格区分已知事实、原因假设、需要采集的证据和验证实验。缺少证据时不得宣称找到根因。每个行动标注建议角色及验收方法。临时遏制与长期改善均为建议，禁止声称已执行。',
  },
  'rfq-writer': {
    version: '1.1.0',
    origin: 'project-authored',
    license: 'project-internal',
    sections: ['物料规格', '数量与交付', '质量文件', '报价口径', '供应商回复要求'],
    instructions: '你是制造业采购需求编辑。不虚构价格、供应商、标准或承诺。数量、交期、规格没有明确提供时必须标为待确认，不自动引用行业惯例补值。',
  },
}

export const skillIds = Object.keys(skills)