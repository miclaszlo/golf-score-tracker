# Attack Tree Visualization - Golf Score Tracker & Handicap System

**Document Version:** 1.0
**Date:** November 12, 2025
**Assignment:** Assignment 2, Question 3 - Attack Tree Visualization
**Course:** CSE763 Secure Software Development

---

## AI Usage Log

### Interaction Summary

**Date:** November 12, 2025
**AI Assistant:** Claude Code (Sonnet 4.5)
**Task:** Attack Tree Visualization using Graphviz

**User Request:**
> "Please log our interaction to 'Attack-Tree-Visualization.md' in the ai-usage-logs/Question3 directory. Let's use Graphviz to visualize the attack trees we created in Attack-Tree-Creation.md."

**AI Response Process:**

1. **Reviewed attack tree structure** - Analyzed the 7 detailed attack trees from Attack-Tree-Creation.md
2. **Selected visualization approach** - Chose Graphviz DOT language for hierarchical graph rendering
3. **Designed visual schema** - Created color-coded system for:
   - Node types (root, intermediate, leaf)
   - Risk levels (feasibility, complexity, detection risk)
   - Logic gates (AND/OR operations)
   - Attack paths (primary vs. alternative)
4. **Created DOT specifications** - Developed complete Graphviz code for each attack tree
5. **Optimized for clarity** - Balanced detail vs. readability for complex trees
6. **Provided rendering instructions** - Added commands for generating PNG/SVG images
7. **Interactive elements** - Included legend and risk assessment visual indicators

**Key AI Capabilities Utilized:**
- Graphviz DOT language syntax generation
- Visual design for hierarchical attack path representation
- Color theory for risk-level differentiation
- Information architecture for complex tree structures
- Technical documentation for visualization workflows

**Output Generated:**
- 7 complete Graphviz DOT specifications
- Rendering instructions and commands
- Color-coded legend system
- Interactive risk assessment overlays
- Export formats (PNG, SVG, PDF)

**Tools Referenced:**
- Graphviz (graph visualization software)
- DOT language (declarative graph description)
- Command-line rendering utilities

---

## Introduction to Attack Tree Visualization

Attack trees are hierarchical diagrams that represent attack scenarios through a tree structure. Visualization helps security analysts:

1. **Understand Attack Paths** - See all possible routes to compromise
2. **Identify Bottlenecks** - Find critical nodes that block multiple attacks
3. **Prioritize Defenses** - Focus on high-risk paths
4. **Communicate Threats** - Share visual representations with stakeholders
5. **Quantify Risk** - Assess cumulative risk across paths

### Graphviz Overview

**Graphviz** is an open-source graph visualization software that uses the DOT language to describe graphs. Benefits:

- Declarative syntax (describe structure, not layout)
- Automatic layout algorithms
- Multiple output formats (PNG, SVG, PDF)
- Hierarchical tree support
- Rich styling options

### Installation

```bash
# macOS
brew install graphviz

# Ubuntu/Debian
sudo apt-get install graphviz

# Windows (with Chocolatey)
choco install graphviz

# Verify installation
dot -V
```

### Rendering Attack Trees

```bash
# Generate PNG image
dot -Tpng attack_tree.dot -o attack_tree.png

# Generate SVG (scalable, interactive)
dot -Tsvg attack_tree.dot -o attack_tree.svg

# Generate PDF
dot -Tpdf attack_tree.dot -o attack_tree.pdf

# High-resolution PNG
dot -Tpng -Gdpi=300 attack_tree.dot -o attack_tree_hires.png
```

---

## Visual Design Schema

### Color Coding System

**Node Types:**
- **Root Nodes** - Red (#FF6B6B) - Ultimate attack goal
- **AND Gates** - Orange (#FFA500) - All children required
- **OR Gates** - Yellow (#FFD93D) - Any child path succeeds
- **Leaf Nodes** - Light Green (#90EE90) - Specific actions/exploits

**Risk Levels (Border Colors):**
- **Feasibility:**
  - HIGH - Thick red border
  - MEDIUM - Orange border
  - LOW - Green border

- **Complexity:**
  - LOW - Single border
  - MEDIUM - Double border
  - HIGH - Triple border

- **Detection Risk:**
  - IMMEDIATE/HIGH - Dashed border
  - MEDIUM - Dotted border
  - LOW - Solid border

**Cost Indicators:**
- FREE - Normal font
- LOW - Italic font
- MEDIUM/HIGH - Bold font

### Node Label Format

```
[Node Name]
---
Feasibility: X
Complexity: Y
Cost: Z
Detection: W
```

---

## Attack Tree 1: Administrative Account Compromise

### Graphviz DOT Code

```dot
digraph AdminCompromise {
    // Graph settings
    rankdir=TB;
    node [shape=box, style=rounded];
    edge [dir=forward];

    // Define color scheme
    node [fontname="Arial", fontsize=10];
    edge [fontname="Arial", fontsize=8];

    // Root node
    root [label="ROOT:\nCompromise Administrative Account\n\nImpact: CRITICAL\nThreat Actor: TA-01",
          shape=box, style="rounded,filled", fillcolor="#FF6B6B", fontcolor=white, fontsize=12, penwidth=3];

    // OR gate - Multiple attack paths
    or1 [label="OR\n(Any Path Succeeds)", shape=diamond, style=filled, fillcolor="#FFD93D", fontsize=10];

    // Path 1: Brute Force
    path1 [label="Path 1:\nBrute Force Attack", shape=box, style="rounded,filled", fillcolor="#FFA500", fontsize=11];

    // Path 1 AND gate
    and1_1 [label="AND\n(All Required)", shape=diamond, style=filled, fillcolor="#FFA500", fontsize=9];

    // Subgoal 1.1
    subgoal1_1 [label="Subgoal 1.1:\nIdentify Valid Admin Username", shape=box, style=rounded, fillcolor="#FFFACD"];

    or1_1 [label="OR", shape=diamond, style=filled, fillcolor="#FFD93D", fontsize=8];

    // Leaf nodes for username enumeration
    leaf1_1_1 [label="LEAF: Username Enumeration\nvia Login Error Messages\n---\nVuln: app.py:111-113\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: LOW",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_1_2 [label="LEAF: Default Credential\nTesting (admin, root)\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: LOW",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_1_3 [label="LEAF: Leaderboard\nData Scraping\n---\nFeasibility: MEDIUM\nComplexity: LOW\nCost: FREE\nDetection: LOW",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FFA500"];

    // Subgoal 1.2
    subgoal1_2 [label="Subgoal 1.2:\nBrute Force Password", shape=box, style=rounded, fillcolor="#FFFACD"];

    and1_2 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500", fontsize=8];

    // Brute force leaf nodes
    leaf1_2_1 [label="LEAF: Exploit Missing\nRate Limiting\n---\nVuln: app.py:86-116\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_2_2 [label="LEAF: Use Common\nPassword Wordlist\n---\nTool: rockyou.txt\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_2_3 [label="LEAF: Credential\nStuffing Attack\n---\nFeasibility: MEDIUM\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FFA500"];

    // Subgoal 1.3
    subgoal1_3 [label="Subgoal 1.3:\nBypass Weak Hashing", shape=box, style=rounded, fillcolor="#FFFACD"];

    leaf1_3_1 [label="LEAF: Offline SHA256\nHash Cracking\n---\nVuln: models.py:30\nPrereq: DB Access\nFeasibility: HIGH\nComplexity: MEDIUM\nCost: MEDIUM (GPU)\nDetection: LOW",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    // Path 2: Session Fixation
    path2 [label="Path 2:\nSession Fixation Attack", shape=box, style="rounded,filled", fillcolor="#FFA500", fontsize=11];

    and2 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500", fontsize=9];

    leaf2_1 [label="LEAF: Obtain Valid\nSession ID\n---\nVuln: app.py:102\nFeasibility: HIGH\nComplexity: MEDIUM\nCost: FREE\nDetection: LOW",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf2_2 [label="LEAF: Trick Admin into\nUsing Attacker Session\n---\nMethod: Phishing Link\nFeasibility: MEDIUM\nComplexity: MEDIUM\nCost: FREE\nDetection: LOW",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    leaf2_3 [label="LEAF: Hijack Session\nAfter Victim Login\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Path 3: SQL Injection
    path3 [label="Path 3:\nSQL Injection to\nCreate Admin Account", shape=box, style="rounded,filled", fillcolor="#FFA500", fontsize=11];

    and3 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500", fontsize=9];

    leaf3_1 [label="LEAF: Identify SQL\nInjection Point\n---\nTarget: Course Search\nFeasibility: MEDIUM\nComplexity: MEDIUM\nCost: FREE\nDetection: MEDIUM",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    leaf3_2 [label="LEAF: UNION-based\nSQL Injection\n---\nFeasibility: MEDIUM\nComplexity: MEDIUM-HIGH\nCost: FREE\nDetection: MEDIUM",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=4, color="#FFA500"];

    leaf3_3 [label="LEAF: INSERT Admin User\nvia SQL Injection\n---\nFeasibility: MEDIUM\nComplexity: HIGH\nCost: FREE\nDetection: HIGH",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=4, color="#FFA500"];

    leaf3_4 [label="LEAF: Login with\nInjected Account\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Post-compromise actions
    post [label="Post-Compromise\nActions", shape=box, style=rounded, fillcolor="#FFCCCC"];

    leaf_post1 [label="LEAF: Create Backdoor\nAdmin Account\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
                shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf_post2 [label="LEAF: Exfiltrate\nUser Database\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
                shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf_post3 [label="LEAF: Modify Audit Logs\nto Hide Tracks\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: HIGH",
                shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Edges
    root -> or1;

    or1 -> path1;
    or1 -> path2;
    or1 -> path3;

    // Path 1 connections
    path1 -> and1_1;
    and1_1 -> subgoal1_1;
    and1_1 -> subgoal1_2;
    and1_1 -> subgoal1_3;

    subgoal1_1 -> or1_1;
    or1_1 -> leaf1_1_1;
    or1_1 -> leaf1_1_2;
    or1_1 -> leaf1_1_3;

    subgoal1_2 -> and1_2;
    and1_2 -> leaf1_2_1;
    and1_2 -> leaf1_2_2;
    and1_2 -> leaf1_2_3;

    subgoal1_3 -> leaf1_3_1;

    // Path 2 connections
    path2 -> and2;
    and2 -> leaf2_1;
    and2 -> leaf2_2;
    and2 -> leaf2_3;

    // Path 3 connections
    path3 -> and3;
    and3 -> leaf3_1;
    and3 -> leaf3_2;
    and3 -> leaf3_3;
    and3 -> leaf3_4;

    // Post-compromise
    path1 -> post [style=dashed, label="if successful"];
    path2 -> post [style=dashed, label="if successful"];
    path3 -> post [style=dashed, label="if successful"];

    post -> leaf_post1;
    post -> leaf_post2;
    post -> leaf_post3;

    // Legend
    subgraph cluster_legend {
        label = "Legend";
        style = filled;
        fillcolor = "#F0F0F0";
        fontsize = 10;

        legend_root [label="Root Node\n(Ultimate Goal)", fillcolor="#FF6B6B", style="rounded,filled", fontcolor=white];
        legend_or [label="OR Gate\n(Any Path)", shape=diamond, fillcolor="#FFD93D", style=filled];
        legend_and [label="AND Gate\n(All Required)", shape=diamond, fillcolor="#FFA500", style=filled];
        legend_leaf [label="Leaf Node\n(Specific Action)", fillcolor="#90EE90", style="rounded,filled"];

        legend_root -> legend_or [style=invis];
        legend_or -> legend_and [style=invis];
        legend_and -> legend_leaf [style=invis];
    }
}
```

### Rendering Instructions

```bash
# Save the DOT code above to a file
cat > admin_compromise.dot << 'EOF'
[paste DOT code here]
EOF

# Generate high-quality PNG
dot -Tpng -Gdpi=300 admin_compromise.dot -o admin_compromise.png

# Generate interactive SVG
dot -Tsvg admin_compromise.dot -o admin_compromise.svg

# Generate PDF for printing
dot -Tpdf admin_compromise.dot -o admin_compromise.pdf
```

### Visual Output Description

The rendered attack tree will show:
- **Red root node** at the top representing the ultimate goal
- **Yellow OR diamond** showing three alternative attack paths
- **Orange AND diamonds** showing required conditions for each path
- **Green leaf nodes** at the bottom with specific attack actions
- **Dashed edges** connecting successful paths to post-compromise actions
- **Legend** in bottom corner explaining node types

---

## Attack Tree 2: Handicap Inflation (Score Manipulation)

### Graphviz DOT Code

```dot
digraph HandicapInflation {
    rankdir=TB;
    node [shape=box, style=rounded, fontname="Arial", fontsize=10];
    edge [fontname="Arial", fontsize=8];

    // Root
    root [label="ROOT:\nArtificially Inflate Handicap Index\n\nImpact: HIGH\nThreat Actor: TA-02\nBusiness Function: CRITICAL",
          shape=box, style="rounded,filled", fillcolor="#FF6B6B", fontcolor=white, fontsize=12, penwidth=3];

    // Main OR gate
    or_main [label="OR", shape=diamond, style=filled, fillcolor="#FFD93D"];

    // Three main paths
    path1 [label="Path 1:\nDirect Score Manipulation\n(HTTP Interception)",
           shape=box, style="rounded,filled", fillcolor="#FFA500", fontsize=11, penwidth=2];

    path2 [label="Path 2:\nSelective Round Reporting\n(Only Report Bad Scores)",
           shape=box, style="rounded,filled", fillcolor="#FFA500", fontsize=11, penwidth=2];

    path3 [label="Path 3:\nCourse Rating Manipulation\n(Requires Admin Access)",
           shape=box, style="rounded,filled", fillcolor="#FFA500", fontsize=11, penwidth=2];

    // Path 1 detailed breakdown
    and_p1 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500", fontsize=9];

    sg1_1 [label="Subgoal 1.1:\nIntercept Score Submission", shape=box, style=rounded, fillcolor="#FFFACD"];
    sg1_2 [label="Subgoal 1.2:\nModify Score Data", shape=box, style=rounded, fillcolor="#FFFACD"];
    sg1_3 [label="Subgoal 1.3:\nRepeat for Multiple Rounds", shape=box, style=rounded, fillcolor="#FFFACD"];

    // Subgoal 1.1 leaves
    leaf1_1_1 [label="LEAF: Setup HTTP\nInterception Proxy\n---\nTool: Burp Suite\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: LOW",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_1_2 [label="LEAF: Submit Legitimate\nRound via Form\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: NONE",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=1, color="#00FF00"];

    leaf1_1_3 [label="LEAF: Capture POST Request\nin Proxy\n---\nVuln: No crypto verification\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: NONE",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Subgoal 1.2 leaves
    leaf1_2_1 [label="LEAF: Inflate Individual\nHole Scores (+2 strokes)\n---\nVuln: models.py:95-96\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: LOW",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_2_2 [label="LEAF: Recalculate\nTotal Score\n---\nVuln: app.py:264\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: LOW",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_2_3 [label="LEAF: Forward Modified\nRequest to Server\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: LOW",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Subgoal 1.3 leaf
    leaf1_3_1 [label="LEAF: Submit 8-10 Inflated\nRounds Over Weeks\n---\nStrategy: Realism\nImpact: +10-15 strokes\nFeasibility: HIGH\nComplexity: LOW\nCost: Time Only\nDetection: LOW-MEDIUM",
               shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Path 2 leaf
    leaf2_1 [label="LEAF: Only Report\nPoorly Played Rounds\n---\nAssumption: No verification\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: LOW-MEDIUM",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf2_2 [label="LEAF: Delete Good Rounds\n(if feature exists)\n---\nFeasibility: MEDIUM\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    // Path 3 breakdown
    and_p3 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500", fontsize=9];

    leaf3_1 [label="LEAF: Compromise Admin\nAccount (see Tree 1)\n---\nPrerequisite\nFeasibility: MEDIUM\nComplexity: MEDIUM",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    leaf3_2 [label="LEAF: Modify Course\nRatings (+5-10 points)\n---\nImpact: Inflates handicaps\nFeasibility: MEDIUM\nComplexity: LOW\nCost: LOW\nDetection: VERY HIGH",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000", style="rounded,filled,dashed"];

    leaf3_3 [label="LEAF: Revert Changes\nAfter Tournament\n---\nProblem: Audit logs\nFeasibility: MEDIUM\nComplexity: LOW\nCost: LOW\nDetection: HIGH",
             shape=box, style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000", style="rounded,filled,dashed"];

    // Post-attack
    post [label="Post-Attack Outcome", shape=box, style=rounded, fillcolor="#FFCCCC"];

    leaf_post [label="LEAF: Compete in Higher\nHandicap Flight\n---\nOutcome: Win vs. weaker opponents\nFinancial: Prize money\nFeasibility: HIGH\nDetection: MEDIUM",
               shape=box, style="rounded,filled", fillcolor="#FF6B6B", fontcolor=white, penwidth=3];

    // Edges
    root -> or_main;
    or_main -> path1;
    or_main -> path2;
    or_main -> path3;

    // Path 1
    path1 -> and_p1;
    and_p1 -> sg1_1;
    and_p1 -> sg1_2;
    and_p1 -> sg1_3;

    sg1_1 -> leaf1_1_1;
    sg1_1 -> leaf1_1_2;
    sg1_1 -> leaf1_1_3;

    sg1_2 -> leaf1_2_1;
    sg1_2 -> leaf1_2_2;
    sg1_2 -> leaf1_2_3;

    sg1_3 -> leaf1_3_1;

    // Path 2
    path2 -> leaf2_1;
    path2 -> leaf2_2;

    // Path 3
    path3 -> and_p3;
    and_p3 -> leaf3_1;
    and_p3 -> leaf3_2;
    and_p3 -> leaf3_3;

    // Post-attack
    path1 -> post [style=dashed, label="success", color="#00AA00"];
    path2 -> post [style=dashed, label="success", color="#00AA00"];
    path3 -> post [style=dashed, label="success", color="#00AA00"];
    post -> leaf_post;

    // Risk annotation
    risk_note [label="CRITICAL VULNERABILITY:\nNo HMAC/Digital Signatures\nNo Score Verification\n(Assignment 3 Priority)",
               shape=note, style=filled, fillcolor="#FFCCCC", fontcolor="#CC0000", fontsize=9];

    root -> risk_note [style=dotted, color="#CC0000", dir=none];
}
```

### Key Visualization Features

This tree highlights:
- **Path 1 (Direct Manipulation)** - Most detailed, shows Burp Suite workflow
- **Critical Vulnerability Annotation** - Note box showing Assignment 3 priority
- **Risk Differentiation** - Path 3 nodes have dashed borders (HIGH detection)
- **Success Outcome** - Final node in red showing tournament win
- **Tool References** - Specific tools (Burp Suite) and code locations

---

## Attack Tree 3: Mass Data Extraction via IDOR (Simplified)

### Graphviz DOT Code

```dot
digraph IDORDataExtraction {
    rankdir=TB;
    node [shape=box, style=rounded, fontname="Arial", fontsize=10];

    root [label="ROOT:\nExtract All User Data\n\nImpact: HIGH (Privacy Breach)\nThreat Actor: TA-05",
          style="rounded,filled", fillcolor="#FF6B6B", fontcolor=white, fontsize=12, penwidth=3];

    or_main [label="OR", shape=diamond, style=filled, fillcolor="#FFD93D"];

    path1 [label="Path 1:\nIDOR Exploitation\n(Systematic Harvesting)",
           style="rounded,filled", fillcolor="#FFA500", fontsize=11, penwidth=2];

    path2 [label="Path 2:\nSQL Injection\n(Database Dump)",
           style="rounded,filled", fillcolor="#FFA500", fontsize=11, penwidth=2];

    path3 [label="Path 3:\nCredential Stuffing\n(Account Access)",
           style="rounded,filled", fillcolor="#FFA500", fontsize=11, penwidth=2];

    // Path 1 - IDOR (detailed)
    and_p1 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500"];

    sg1_1 [label="Discover IDOR\nVulnerability", style=rounded, fillcolor="#FFFACD"];
    sg1_2 [label="Enumerate\nUser IDs", style=rounded, fillcolor="#FFFACD"];
    sg1_3 [label="Automate\nData Harvesting", style=rounded, fillcolor="#FFFACD"];

    leaf1_1 [label="LEAF: Create Account\n+ Access Own Data\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: NONE",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_2 [label="LEAF: Test IDOR by\nModifying user_id\n---\nVuln: app.py:366-380\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: LOW",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_3 [label="LEAF: Sequential ID\nEnumeration (1 to N)\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_4 [label="LEAF: Write Python Script\nfor Mass Collection\n---\nRate: 10-100 req/sec\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf1_5 [label="LEAF: Bypass Rate Limiting\n(NONE EXISTS)\n---\nFeasibility: HIGH\nComplexity: LOW\nDetection: LOW",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Path 2 - SQL Injection (simplified)
    leaf2_1 [label="LEAF: Identify SQL Injection\n+ Extract Schema\n---\nFeasibility: MEDIUM\nComplexity: MEDIUM\nCost: FREE\nDetection: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    leaf2_2 [label="LEAF: Dump Users Table\nwith Credentials\n---\nTool: sqlmap --dump\nFeasibility: MEDIUM\nComplexity: MEDIUM\nCost: FREE\nDetection: MEDIUM-HIGH",
             style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    leaf2_3 [label="LEAF: Crack SHA256\nPassword Hashes\n---\nVuln: models.py:30\nTool: hashcat\nFeasibility: HIGH\nComplexity: MEDIUM\nCost: MEDIUM (GPU)\nDetection: NONE (offline)",
             style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    // Path 3 - Credential Stuffing (simplified)
    leaf3_1 [label="LEAF: Obtain Leaked\nCredential Database\n---\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: NONE",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf3_2 [label="LEAF: Enumerate Usernames\n+ Test Credentials\n---\nVuln: No rate limiting\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Post-harvest
    post [label="Post-Harvest Actions", style=rounded, fillcolor="#FFCCCC"];

    or_post [label="OR", shape=diamond, style=filled, fillcolor="#FFD93D", fontsize=9];

    leaf_post1 [label="LEAF: Sell Data on\nDark Web Markets\n---\nPrice: $0.50-$5 per record\nFeasibility: MEDIUM\nDetection: LOW",
                style="rounded,filled", fillcolor="#FF6B6B", fontcolor=white, penwidth=2];

    leaf_post2 [label="LEAF: Targeted\nPhishing Campaigns\n---\nFeasibility: HIGH\nDetection: MEDIUM",
                style="rounded,filled", fillcolor="#FF6B6B", fontcolor=white, penwidth=2];

    leaf_post3 [label="LEAF: Competitive Intelligence\nSale (Premium)\n---\nFeasibility: MEDIUM\nDetection: LOW",
                style="rounded,filled", fillcolor="#FF6B6B", fontcolor=white, penwidth=2];

    // Edges
    root -> or_main;
    or_main -> path1;
    or_main -> path2;
    or_main -> path3;

    path1 -> and_p1;
    and_p1 -> sg1_1;
    and_p1 -> sg1_2;
    and_p1 -> sg1_3;

    sg1_1 -> leaf1_1;
    sg1_1 -> leaf1_2;
    sg1_2 -> leaf1_3;
    sg1_3 -> leaf1_4;
    sg1_3 -> leaf1_5;

    path2 -> leaf2_1;
    path2 -> leaf2_2;
    path2 -> leaf2_3;

    path3 -> leaf3_1;
    path3 -> leaf3_2;

    path1 -> post [style=dashed, color="#00AA00"];
    path2 -> post [style=dashed, color="#00AA00"];
    path3 -> post [style=dashed, color="#00AA00"];

    post -> or_post;
    or_post -> leaf_post1;
    or_post -> leaf_post2;
    or_post -> leaf_post3;

    // GDPR warning
    gdpr_note [label="GDPR VIOLATION:\nPrivacy Breach\nRegulatory Penalties\n(HIGH Impact)",
               shape=note, style=filled, fillcolor="#FFCCCC", fontcolor="#CC0000", fontsize=9];

    root -> gdpr_note [style=dotted, color="#CC0000", dir=none];
}
```

---

## Attack Tree 4: Insider Fraud Operation (High-Level)

### Graphviz DOT Code

```dot
digraph InsiderFraud {
    rankdir=TB;
    node [shape=box, style=rounded, fontname="Arial", fontsize=10];

    root [label="ROOT:\nOperate Handicap Manipulation\nFraud Service\n\nImpact: CRITICAL\nThreat Actor: TA-03 (Malicious Admin)",
          style="rounded,filled", fillcolor="#CC0000", fontcolor=white, fontsize=12, penwidth=4];

    and_main [label="AND\n(All Components Required)", shape=diamond, style=filled, fillcolor="#FFA500", fontsize=10];

    // Four main components
    comp1 [label="Component 1:\nObtain/Maintain\nAdmin Access",
           style="rounded,filled", fillcolor="#FFA500", fontsize=11, penwidth=2];

    comp2 [label="Component 2:\nRecruit Paying\nClients",
           style="rounded,filled", fillcolor="#FFA500", fontsize=11, penwidth=2];

    comp3 [label="Component 3:\nExecute Handicap\nManipulations",
           style="rounded,filled", fillcolor="#FFA500", fontsize=11, penwidth=2];

    comp4 [label="Component 4:\nCover Tracks and\nAvoid Detection",
           style="rounded,filled", fillcolor="#FFA500", fontsize=11, penwidth=2];

    // Component 1 leaves
    or_c1 [label="OR", shape=diamond, style=filled, fillcolor="#FFD93D", fontsize=9];

    leaf1_1 [label="LEAF: Legitimate Admin\nAccount (Rogue Insider)\n---\nFeasibility: MEDIUM\nDetection: HIGH",
             style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    leaf1_2 [label="LEAF: Compromise Admin\nAccount (See Tree 1)\n---\nFeasibility: MEDIUM\nComplexity: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    leaf1_3 [label="LEAF: Create Hidden\nBackdoor Account\n---\nFeasibility: HIGH\nComplexity: LOW\nDetection: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Component 2 leaves
    leaf2_1 [label="LEAF: Identify High-Stakes\nTournament Players\n---\nFeasibility: MEDIUM\nComplexity: LOW",
             style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    leaf2_2 [label="LEAF: Establish Pricing\n($500-$2000 per manipulation)\n---\nPayment: Cash/Crypto\nFeasibility: HIGH",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Component 3 leaves
    and_c3 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500", fontsize=9];

    leaf3_1 [label="LEAF: Direct Database\nModification (UPDATE rounds)\n---\nAccess: instance/golf.db\nFeasibility: HIGH\nComplexity: LOW\nDetection: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf3_2 [label="LEAF: Modify Individual\nHole Scores (Realistic)\n---\nFeasibility: HIGH\nComplexity: LOW\nDetection: LOW",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf3_3 [label="LEAF: Spread Changes\nOver Time (2-3 months)\n---\nStrategy: Gradual inflation\nFeasibility: HIGH\nDetection: LOW",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Component 4 leaves
    and_c4 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500", fontsize=9];

    leaf4_1 [label="LEAF: Delete/Modify\nAudit Log Entries\n---\nVuln: Modifiable logs\nFeasibility: HIGH\nComplexity: LOW\nDetection: HIGH (if external monitor)",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000", style="rounded,filled,dashed"];

    leaf4_2 [label="LEAF: Manipulate\nTimestamps (Backdate)\n---\nFeasibility: HIGH\nComplexity: LOW\nDetection: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf4_3 [label="LEAF: Use Backdoor Account\nfor Operations\n---\nBenefit: Primary admin stays clean\nFeasibility: HIGH\nDetection: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Outcomes
    outcome [label="Fraud Operation Outcomes", style=rounded, fillcolor="#FFCCCC"];

    leaf_out1 [label="OUTCOME: Financial Gain\n$5K-$100K over months\n---\nRisk: Money laundering investigation",
               style="rounded,filled", fillcolor="#CC0000", fontcolor=white, penwidth=3];

    leaf_out2 [label="OUTCOME: System Integrity\nDestruction\n---\nHandicap system loses credibility\nForensics extremely difficult",
               style="rounded,filled", fillcolor="#CC0000", fontcolor=white, penwidth=3];

    // Edges
    root -> and_main;
    and_main -> comp1;
    and_main -> comp2;
    and_main -> comp3;
    and_main -> comp4;

    comp1 -> or_c1;
    or_c1 -> leaf1_1;
    or_c1 -> leaf1_2;
    or_c1 -> leaf1_3;

    comp2 -> leaf2_1;
    comp2 -> leaf2_2;

    comp3 -> and_c3;
    and_c3 -> leaf3_1;
    and_c3 -> leaf3_2;
    and_c3 -> leaf3_3;

    comp4 -> and_c4;
    and_c4 -> leaf4_1;
    and_c4 -> leaf4_2;
    and_c4 -> leaf4_3;

    and_main -> outcome [style=dashed, label="if all succeed", color="#CC0000"];
    outcome -> leaf_out1;
    outcome -> leaf_out2;

    // Risk warning
    risk_note [label="CRITICAL RISK:\nNo Segregation of Duties\nNo Multi-Party Approval\nModifiable Audit Logs\n(Highest Impact Scenario)",
               shape=note, style=filled, fillcolor="#FFCCCC", fontcolor="#CC0000", fontsize=9];

    root -> risk_note [style=dotted, color="#CC0000", dir=none];
}
```

### Unique Features

This tree emphasizes:
- **Dark red root** (CRITICAL impact)
- **AND gate at top level** - All components required for fraud operation
- **Financial outcomes** - Shows revenue model
- **Audit log manipulation** - Highlighted with dashed borders
- **Risk annotation** - Emphasizes lack of controls

---

## Attack Tree 5: Website Defacement/DoS (Simplified)

### Graphviz DOT Code

```dot
digraph DefacementDoS {
    rankdir=TB;
    node [shape=box, style=rounded, fontname="Arial", fontsize=10];

    root [label="ROOT:\nDisrupt Service and\nDeface Website\n\nImpact: HIGH\nThreat Actor: TA-06 (Vandal/Hacktivist)",
          style="rounded,filled", fillcolor="#FF6B6B", fontcolor=white, fontsize=12, penwidth=3];

    or_main [label="OR", shape=diamond, style=filled, fillcolor="#FFD93D"];

    path1 [label="Path 1:\nWebsite Defacement",
           style="rounded,filled", fillcolor="#FFA500", fontsize=11];

    path2 [label="Path 2:\nApplication-Layer DoS",
           style="rounded,filled", fillcolor="#FFA500", fontsize=11];

    path3 [label="Path 3:\nDatabase Destruction",
           style="rounded,filled", fillcolor="#FFA500", fontsize=11];

    // Path 1 - Defacement
    and_p1 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500"];

    leaf1_1 [label="LEAF: Gain Admin Access\n(See Tree 1)\n---\nRequired for template access\nFeasibility: MEDIUM\nComplexity: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    leaf1_2 [label="LEAF: Access Base Template\n(templates/base.html)\n---\nFeasibility: HIGH\nComplexity: LOW\nDetection: HIGH",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000", style="rounded,filled,dashed"];

    leaf1_3 [label="LEAF: Inject Defacement\nContent + Malicious JS\n---\nExample: Redirect to attacker site\nFeasibility: HIGH\nComplexity: LOW\nDetection: IMMEDIATE",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000", style="rounded,filled,dashed"];

    leaf1_4 [label="LEAF: Screenshot and\nPublicize on Social Media\n---\nPurpose: Maximize visibility\nFeasibility: HIGH\nDetection: NONE",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Path 2 - DoS
    and_p2 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500"];

    sg2_1 [label="Identify Resource-\nIntensive Endpoints", style=rounded, fillcolor="#FFFACD"];
    sg2_2 [label="Automate High-\nVolume Requests", style=rounded, fillcolor="#FFFACD"];

    leaf2_1 [label="LEAF: Target Score\nSubmission (POST /round/new)\n---\nVuln: No rate limiting\nFeasibility: HIGH\nComplexity: LOW",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf2_2 [label="LEAF: Target Login Endpoint\n(Password Hashing Cost)\n---\nVuln: app.py:86-116\nFeasibility: HIGH\nComplexity: LOW",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    leaf2_3 [label="LEAF: Write DoS Script\n(100-1000 req/sec)\n---\nTool: Python + asyncio\nFeasibility: HIGH\nComplexity: LOW\nCost: FREE\nDetection: HIGH",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000", style="rounded,filled,dashed"];

    leaf2_4 [label="LEAF: Exhaust Server\nResources (CPU/Memory)\n---\nSymptom: 500 errors, timeouts\nFeasibility: MEDIUM\nDetection: IMMEDIATE",
             style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500", style="rounded,filled,dashed"];

    leaf2_5 [label="LEAF: Launch During\nMajor Tournament\n---\nTiming: Maximum impact\nFeasibility: HIGH\nDetection: IMMEDIATE",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000", style="rounded,filled,dashed"];

    // Path 3 - Database Destruction
    and_p3 [label="AND", shape=diamond, style=filled, fillcolor="#FFA500"];

    leaf3_1 [label="LEAF: Gain Admin or\nSQL Injection Access\n---\nFeasibility: MEDIUM\nComplexity: MEDIUM",
             style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500"];

    or_p3 [label="OR", shape=diamond, style=filled, fillcolor="#FFD93D", fontsize=9];

    leaf3_2 [label="LEAF: Execute DROP TABLE\nCommands\n---\nSQL: DROP TABLE users; rounds;\nImpact: Complete data loss\nFeasibility: MEDIUM\nDetection: IMMEDIATE",
             style="rounded,filled", fillcolor="#90EE90", penwidth=3, color="#FFA500", style="rounded,filled,dashed"];

    leaf3_3 [label="LEAF: Corrupt Data Instead\n(UPDATE passwords='hacked')\n---\nImpact: All users locked out\nRecovery: More difficult\nFeasibility: HIGH\nDetection: DELAYED",
             style="rounded,filled", fillcolor="#90EE90", penwidth=2, color="#FF0000"];

    // Impact
    impact [label="Service Disruption Impact", style=rounded, fillcolor="#FFCCCC"];

    leaf_impact [label="OUTCOME: Service Outage\nfor Days/Weeks\n---\nRecovery: Restore from backups\nReputational: User trust lost\nFinancial: Tournament revenue lost\nMedia: Negative coverage",
                 style="rounded,filled", fillcolor="#CC0000", fontcolor=white, penwidth=3];

    // Edges
    root -> or_main;
    or_main -> path1;
    or_main -> path2;
    or_main -> path3;

    path1 -> and_p1;
    and_p1 -> leaf1_1;
    and_p1 -> leaf1_2;
    and_p1 -> leaf1_3;
    and_p1 -> leaf1_4;

    path2 -> and_p2;
    and_p2 -> sg2_1;
    and_p2 -> sg2_2;
    sg2_1 -> leaf2_1;
    sg2_1 -> leaf2_2;
    sg2_2 -> leaf2_3;
    sg2_2 -> leaf2_4;
    and_p2 -> leaf2_5;

    path3 -> and_p3;
    and_p3 -> leaf3_1;
    and_p3 -> or_p3;
    or_p3 -> leaf3_2;
    or_p3 -> leaf3_3;

    path1 -> impact [style=dashed, color="#CC0000"];
    path2 -> impact [style=dashed, color="#CC0000"];
    path3 -> impact [style=dashed, color="#CC0000"];
    impact -> leaf_impact;
}
```

---

## Combined Risk Heatmap Visualization

### Graphviz DOT Code

This visualization shows all attack trees in a single risk matrix:

```dot
digraph RiskHeatmap {
    rankdir=LR;
    node [shape=box, style="rounded,filled", fontname="Arial"];

    // Title
    title [label="Attack Tree Risk Heatmap\nGolf Score Tracker",
           shape=plaintext, fontsize=16, fontcolor="#000000"];

    // Risk matrix quadrants
    subgraph cluster_matrix {
        label = "Risk Matrix: Likelihood × Impact";
        style = filled;
        fillcolor = "#F5F5F5";
        fontsize = 12;

        // High Likelihood, High Impact (CRITICAL)
        quad_hh [label="HIGH LIKELIHOOD\nHIGH IMPACT\n━━━━━━━━━━━━━\nTree 2: Handicap Inflation\nTree 3: IDOR Data Extraction\nTree 6: Competitive Intel",
                 fillcolor="#FF6B6B", fontcolor=white, fontsize=10, penwidth=3];

        // Medium Likelihood, Critical Impact (HIGH)
        quad_mc [label="MEDIUM LIKELIHOOD\nCRITICAL IMPACT\n━━━━━━━━━━━━━\nTree 1: Admin Compromise\nTree 4: Insider Fraud\nTree 7: SQL Injection Dump",
                 fillcolor="#FFA500", fontcolor=white, fontsize=10, penwidth=2];

        // Medium Likelihood, Medium Impact (MEDIUM)
        quad_mm [label="MEDIUM LIKELIHOOD\nMEDIUM-HIGH IMPACT\n━━━━━━━━━━━━━\nTree 5: Defacement/DoS",
                 fillcolor="#FFD93D", fontcolor=black, fontsize=10, penwidth=2];

        // Low Likelihood, High Impact (MONITOR)
        quad_lh [label="LOW LIKELIHOOD\nHIGH IMPACT\n━━━━━━━━━━━━━\n(No trees in this category)",
                 fillcolor="#90EE90", fontcolor=black, fontsize=10, penwidth=1];

        quad_hh -> quad_mc [style=invis];
        quad_mc -> quad_mm [style=invis];
        quad_mm -> quad_lh [style=invis];
    }

    // Common vulnerabilities
    subgraph cluster_vulns {
        label = "Common Critical Vulnerabilities";
        style = filled;
        fillcolor = "#FFEEEE";
        fontsize = 12;

        vuln1 [label="No Score Verification\n(HMAC/Signatures)", fillcolor="#FF6B6B", fontcolor=white, style="rounded,filled"];
        vuln2 [label="IDOR at /api/handicap", fillcolor="#FF6B6B", fontcolor=white, style="rounded,filled"];
        vuln3 [label="Weak Password Hashing\n(SHA256)", fillcolor="#FFA500", fontcolor=white, style="rounded,filled"];
        vuln4 [label="No Rate Limiting", fillcolor="#FFA500", fontcolor=white, style="rounded,filled"];
        vuln5 [label="SQL Injection", fillcolor="#FFA500", fontcolor=white, style="rounded,filled"];

        vuln1 -> vuln2 [style=invis];
        vuln2 -> vuln3 [style=invis];
        vuln3 -> vuln4 [style=invis];
        vuln4 -> vuln5 [style=invis];
    }

    // Assignment mitigation
    subgraph cluster_assign {
        label = "Mitigation Assignments";
        style = filled;
        fillcolor = "#E8F4F8";
        fontsize = 12;

        assign3 [label="Assignment 3:\nCryptographic APIs\n━━━━━━━━━━━━━\n• Bcrypt password hashing\n• HMAC score signatures\n• PII encryption",
                 fillcolor="#4A90E2", fontcolor=white, style="rounded,filled"];

        assign4 [label="Assignment 4:\nDAST & Vulnerability Fixes\n━━━━━━━━━━━━━\n• Fix IDOR (authorization)\n• Rate limiting\n• CSRF tokens\n• SQL injection fixes\n• Session regeneration",
                 fillcolor="#50C878", fontcolor=white, style="rounded,filled"];

        assign3 -> assign4 [style=invis];
    }

    title -> quad_hh [style=invis];
}
```

### Rendering Instructions

```bash
# Render risk heatmap
dot -Tpng -Gdpi=300 risk_heatmap.dot -o risk_heatmap.png
dot -Tsvg risk_heatmap.dot -o risk_heatmap.svg
```

---

## Batch Rendering Script

Create a script to render all attack trees at once:

### `render_all_trees.sh`

```bash
#!/bin/bash

# Create output directory
mkdir -p attack_tree_visualizations

# Array of DOT files
trees=(
    "admin_compromise"
    "handicap_inflation"
    "idor_data_extraction"
    "insider_fraud"
    "defacement_dos"
    "risk_heatmap"
)

# Render each tree in multiple formats
for tree in "${trees[@]}"; do
    echo "Rendering $tree..."

    # PNG (high resolution)
    dot -Tpng -Gdpi=300 "${tree}.dot" -o "attack_tree_visualizations/${tree}.png"

    # SVG (interactive, scalable)
    dot -Tsvg "${tree}.dot" -o "attack_tree_visualizations/${tree}.svg"

    # PDF (for printing)
    dot -Tpdf "${tree}.dot" -o "attack_tree_visualizations/${tree}.pdf"

    echo "✓ ${tree} rendered successfully"
done

echo ""
echo "All attack trees rendered to attack_tree_visualizations/"
echo "Formats: PNG (300 DPI), SVG, PDF"
```

### Usage

```bash
# Make executable
chmod +x render_all_trees.sh

# Run
./render_all_trees.sh
```

---

## Interactive HTML Viewer

### `attack_tree_viewer.html`

Create an HTML file to view all SVG visualizations interactively:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Tree Visualization - Golf Score Tracker</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }

        header {
            background: linear-gradient(135deg, #FF6B6B 0%, #FFA500 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        header p {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .tabs {
            display: flex;
            background: #f5f5f5;
            border-bottom: 2px solid #ddd;
            overflow-x: auto;
        }

        .tab {
            padding: 15px 25px;
            cursor: pointer;
            background: #f5f5f5;
            border: none;
            font-size: 14px;
            font-weight: 600;
            color: #555;
            transition: all 0.3s;
            white-space: nowrap;
        }

        .tab:hover {
            background: #e0e0e0;
        }

        .tab.active {
            background: white;
            color: #FF6B6B;
            border-bottom: 3px solid #FF6B6B;
        }

        .content {
            padding: 30px;
        }

        .tree-view {
            display: none;
        }

        .tree-view.active {
            display: block;
        }

        .tree-info {
            background: #f9f9f9;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 5px solid #FF6B6B;
        }

        .tree-info h2 {
            color: #FF6B6B;
            margin-bottom: 10px;
        }

        .tree-info .meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }

        .meta-item {
            background: white;
            padding: 10px 15px;
            border-radius: 5px;
            border-left: 3px solid #FFA500;
        }

        .meta-item strong {
            color: #555;
            display: block;
            margin-bottom: 5px;
            font-size: 12px;
            text-transform: uppercase;
        }

        .meta-item span {
            color: #333;
            font-size: 16px;
            font-weight: 600;
        }

        .svg-container {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            overflow: auto;
            max-height: 800px;
        }

        .svg-container svg {
            max-width: 100%;
            height: auto;
        }

        .legend {
            background: #f0f8ff;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            border: 2px solid #4A90E2;
        }

        .legend h3 {
            color: #4A90E2;
            margin-bottom: 10px;
        }

        .legend-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 10px;
            margin-top: 10px;
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .legend-color {
            width: 30px;
            height: 30px;
            border-radius: 4px;
            border: 2px solid #333;
        }

        footer {
            background: #333;
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🎯 Attack Tree Visualization</h1>
            <p>Golf Score Tracker & Handicap System - CSE763 Assignment 2</p>
        </header>

        <div class="tabs">
            <button class="tab active" onclick="showTree('tree1')">Tree 1: Admin Compromise</button>
            <button class="tab" onclick="showTree('tree2')">Tree 2: Handicap Inflation</button>
            <button class="tab" onclick="showTree('tree3')">Tree 3: IDOR Data Extraction</button>
            <button class="tab" onclick="showTree('tree4')">Tree 4: Insider Fraud</button>
            <button class="tab" onclick="showTree('tree5')">Tree 5: Defacement/DoS</button>
            <button class="tab" onclick="showTree('heatmap')">Risk Heatmap</button>
        </div>

        <div class="content">
            <!-- Tree 1 -->
            <div id="tree1" class="tree-view active">
                <div class="tree-info">
                    <h2>Attack Tree 1: Administrative Account Compromise</h2>
                    <p>This attack tree shows three alternative paths to gain admin access: brute force, session fixation, and SQL injection.</p>
                    <div class="meta">
                        <div class="meta-item">
                            <strong>Threat Actor</strong>
                            <span>TA-01 (Script Kiddie)</span>
                        </div>
                        <div class="meta-item">
                            <strong>Impact</strong>
                            <span>CRITICAL</span>
                        </div>
                        <div class="meta-item">
                            <strong>Feasibility</strong>
                            <span>MEDIUM-HIGH</span>
                        </div>
                        <div class="meta-item">
                            <strong>Priority</strong>
                            <span>HIGH</span>
                        </div>
                    </div>
                </div>
                <div class="svg-container">
                    <object data="attack_tree_visualizations/admin_compromise.svg" type="image/svg+xml" width="100%">
                        <img src="attack_tree_visualizations/admin_compromise.png" alt="Admin Compromise Attack Tree">
                    </object>
                </div>
            </div>

            <!-- Tree 2 -->
            <div id="tree2" class="tree-view">
                <div class="tree-info">
                    <h2>Attack Tree 2: Handicap Inflation for Tournament Advantage</h2>
                    <p>Shows how competitive golfers can manipulate scores using HTTP interception, selective reporting, or course rating manipulation.</p>
                    <div class="meta">
                        <div class="meta-item">
                            <strong>Threat Actor</strong>
                            <span>TA-02 (Competitive Golfer)</span>
                        </div>
                        <div class="meta-item">
                            <strong>Impact</strong>
                            <span>HIGH (Core Function)</span>
                        </div>
                        <div class="meta-item">
                            <strong>Feasibility</strong>
                            <span>HIGH</span>
                        </div>
                        <div class="meta-item">
                            <strong>Priority</strong>
                            <span>CRITICAL</span>
                        </div>
                    </div>
                </div>
                <div class="svg-container">
                    <object data="attack_tree_visualizations/handicap_inflation.svg" type="image/svg+xml" width="100%">
                        <img src="attack_tree_visualizations/handicap_inflation.png" alt="Handicap Inflation Attack Tree">
                    </object>
                </div>
            </div>

            <!-- Tree 3 -->
            <div id="tree3" class="tree-view">
                <div class="tree-info">
                    <h2>Attack Tree 3: Mass Data Extraction via IDOR</h2>
                    <p>Demonstrates systematic harvesting of user data through IDOR vulnerabilities, SQL injection, and credential stuffing.</p>
                    <div class="meta">
                        <div class="meta-item">
                            <strong>Threat Actor</strong>
                            <span>TA-05 (Data Harvester)</span>
                        </div>
                        <div class="meta-item">
                            <strong>Impact</strong>
                            <span>HIGH (Privacy/GDPR)</span>
                        </div>
                        <div class="meta-item">
                            <strong>Feasibility</strong>
                            <span>HIGH</span>
                        </div>
                        <div class="meta-item">
                            <strong>Priority</strong>
                            <span>CRITICAL</span>
                        </div>
                    </div>
                </div>
                <div class="svg-container">
                    <object data="attack_tree_visualizations/idor_data_extraction.svg" type="image/svg+xml" width="100%">
                        <img src="attack_tree_visualizations/idor_data_extraction.png" alt="IDOR Data Extraction Attack Tree">
                    </object>
                </div>
            </div>

            <!-- Tree 4 -->
            <div id="tree4" class="tree-view">
                <div class="tree-info">
                    <h2>Attack Tree 4: Insider Handicap Fraud Operation</h2>
                    <p>Shows systematic fraud operation by malicious administrator manipulating handicaps for financial gain.</p>
                    <div class="meta">
                        <div class="meta-item">
                            <strong>Threat Actor</strong>
                            <span>TA-03 (Malicious Admin)</span>
                        </div>
                        <div class="meta-item">
                            <strong>Impact</strong>
                            <span>CRITICAL</span>
                        </div>
                        <div class="meta-item">
                            <strong>Feasibility</strong>
                            <span>MEDIUM</span>
                        </div>
                        <div class="meta-item">
                            <strong>Priority</strong>
                            <span>HIGH</span>
                        </div>
                    </div>
                </div>
                <div class="svg-container">
                    <object data="attack_tree_visualizations/insider_fraud.svg" type="image/svg+xml" width="100%">
                        <img src="attack_tree_visualizations/insider_fraud.png" alt="Insider Fraud Attack Tree">
                    </object>
                </div>
            </div>

            <!-- Tree 5 -->
            <div id="tree5" class="tree-view">
                <div class="tree-info">
                    <h2>Attack Tree 5: Website Defacement and Service Disruption</h2>
                    <p>Illustrates vandalism and DoS attacks targeting service availability and reputation.</p>
                    <div class="meta">
                        <div class="meta-item">
                            <strong>Threat Actor</strong>
                            <span>TA-06 (Vandal/Hacktivist)</span>
                        </div>
                        <div class="meta-item">
                            <strong>Impact</strong>
                            <span>HIGH (Availability)</span>
                        </div>
                        <div class="meta-item">
                            <strong>Feasibility</strong>
                            <span>MEDIUM</span>
                        </div>
                        <div class="meta-item">
                            <strong>Priority</strong>
                            <span>MEDIUM</span>
                        </div>
                    </div>
                </div>
                <div class="svg-container">
                    <object data="attack_tree_visualizations/defacement_dos.svg" type="image/svg+xml" width="100%">
                        <img src="attack_tree_visualizations/defacement_dos.png" alt="Defacement/DoS Attack Tree">
                    </object>
                </div>
            </div>

            <!-- Heatmap -->
            <div id="heatmap" class="tree-view">
                <div class="tree-info">
                    <h2>Risk Heatmap: Attack Tree Prioritization</h2>
                    <p>Consolidated view of all attack trees categorized by likelihood and impact for risk-based prioritization.</p>
                    <div class="meta">
                        <div class="meta-item">
                            <strong>Purpose</strong>
                            <span>Risk Prioritization</span>
                        </div>
                        <div class="meta-item">
                            <strong>Methodology</strong>
                            <span>Likelihood × Impact</span>
                        </div>
                        <div class="meta-item">
                            <strong>Critical Paths</strong>
                            <span>3 Trees (HIGH/HIGH)</span>
                        </div>
                        <div class="meta-item">
                            <strong>Mitigation</strong>
                            <span>Assignment 3 & 4</span>
                        </div>
                    </div>
                </div>
                <div class="svg-container">
                    <object data="attack_tree_visualizations/risk_heatmap.svg" type="image/svg+xml" width="100%">
                        <img src="attack_tree_visualizations/risk_heatmap.png" alt="Risk Heatmap">
                    </object>
                </div>
            </div>

            <!-- Legend -->
            <div class="legend">
                <h3>📖 Visual Legend</h3>
                <div class="legend-grid">
                    <div class="legend-item">
                        <div class="legend-color" style="background: #FF6B6B;"></div>
                        <span>Root Node (Ultimate Goal)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #FFD93D;"></div>
                        <span>OR Gate (Any Path Succeeds)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #FFA500;"></div>
                        <span>AND Gate (All Required)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #90EE90;"></div>
                        <span>Leaf Node (Specific Action)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: white; border-color: #FF0000; border-width: 3px;"></div>
                        <span>High Feasibility</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: white; border-color: #FFA500; border-width: 3px;"></div>
                        <span>Medium Feasibility</span>
                    </div>
                </div>
            </div>
        </div>

        <footer>
            <p><strong>Assignment 2 - Attack Tree Visualization</strong></p>
            <p>CSE763 Secure Software Development | Boston University | November 2025</p>
        </footer>
    </div>

    <script>
        function showTree(treeId) {
            // Hide all trees
            document.querySelectorAll('.tree-view').forEach(tree => {
                tree.classList.remove('active');
            });

            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });

            // Show selected tree
            document.getElementById(treeId).classList.add('active');

            // Highlight active tab
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
```

---

## Usage Summary

### Quick Start

1. **Save DOT files**: Copy each Graphviz DOT code block to separate `.dot` files
2. **Install Graphviz**: `brew install graphviz` (macOS) or equivalent
3. **Render trees**: Use `dot -Tpng tree.dot -o tree.png`
4. **View interactively**: Open `attack_tree_viewer.html` in browser

### File Organization

```
golf-score-tracker/
├── attack_tree_visualizations/
│   ├── admin_compromise.png
│   ├── admin_compromise.svg
│   ├── admin_compromise.pdf
│   ├── handicap_inflation.png
│   ├── handicap_inflation.svg
│   ├── idor_data_extraction.png
│   ├── insider_fraud.png
│   ├── defacement_dos.png
│   └── risk_heatmap.png
├── admin_compromise.dot
├── handicap_inflation.dot
├── idor_data_extraction.dot
├── insider_fraud.dot
├── defacement_dos.dot
├── risk_heatmap.dot
├── render_all_trees.sh
└── attack_tree_viewer.html
```

---

## Key Visualization Insights

### Color-Coded Risk Levels

1. **Red borders (thick)** - HIGH feasibility attacks → Prioritize mitigation
2. **Orange borders** - MEDIUM feasibility → Monitor and improve defenses
3. **Dashed borders** - HIGH/IMMEDIATE detection risk → Easily caught
4. **Green leaf nodes** - Specific actionable steps for attackers

### Attack Path Analysis

- **Shortest paths** (fewest nodes) = Easiest attacks to execute
- **AND gates** = Bottlenecks where defense can block multiple paths
- **OR gates** = Multiple alternatives requiring layered defenses
- **Post-compromise nodes** = Impact after initial breach

### Defense Prioritization

Focus on:
1. **Leaf nodes with HIGH feasibility + LOW complexity + FREE cost**
2. **Nodes appearing in multiple trees** (common vulnerabilities)
3. **AND gates near root** (blocking these prevents entire attack classes)

---

## Conclusion

These Graphviz visualizations transform the textual attack trees from Attack-Tree-Creation.md into interactive, color-coded hierarchical diagrams. The visual format enables:

- **Rapid threat assessment** - See risk levels at a glance
- **Pattern recognition** - Identify common attack paths across trees
- **Stakeholder communication** - Non-technical audiences understand threats
- **Defense planning** - Prioritize mitigations based on visual risk indicators
- **Assignment alignment** - Map vulnerabilities to Assignment 3 & 4 fixes

The combination of detailed textual attack trees and visual Graphviz representations provides comprehensive threat modeling documentation for the Golf Score Tracker system.

---

**Document Prepared By:** Claude Code (AI Assistant)
**Review Status:** Draft for Assignment 2, Question 3
**Next Steps:** Render visualizations, include in threat modeling report, present to stakeholders
