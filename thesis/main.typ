#import "@preview/prometeu-thesis:1.0.0": colors, thesis

#show: thesis(
  author: "Eduardo André Silva Cunha",
  title: [Dynamic Attack Graph Generation \ Using Threat Intelligence and \ Threat Modeling],
  date: [September 2026],
  supervisors: (
    [João Marco Cardoso da Silva],
  ),
  cover-images: (image("logos/uminho/color/UM.jpg"), image("logos/uminho/color/EE.jpg")),
  cover-gray-images: (image("logos/uminho/gray/UM.jpg"), image("logos/uminho/gray/EE.jpg")),
  school: [School of Engineering],
  degree: [Master's Dissertation in Informatics Engineering],
  // Set this to "pt" for Portuguese titles
  language: "en",
)

// Setup glossary and acronyms
#import "@preview/glossarium:0.5.10": *

#show: make-glossary
#let acronyms-data = yaml("acronyms.yml")
#let glossary-data = yaml("glossary.yml")
#register-glossary(acronyms-data + glossary-data)

#let show-acronyms = print-glossary(
  acronyms-data,
  // Change this to your liking
  show-all: true,
  disable-back-references: true,
  user-print-title: entry => {
    let description = if entry.long != none { h(0.5em) + entry.long + [.] }
    text(weight: "bold", entry.short) + description
  },
)

#let show-glossary = print-glossary(
  glossary-data,
  // Change this to your liking
  show-all: true,
  disable-back-references: true,
  user-print-title: entry => {
    let title = if entry.long == none { entry.short } else { entry.long }
    let display = if type(title) == str and title.len() > 0 {
      upper(title.first()) + title.slice(1)
    } else { title }
    text(weight: "bold", display) + h(0.5em) + entry.description
  },
  user-print-description: entry => if entry.description != none { [.] },
  description-separator: [],
)

#show cite: it => text(fill: black, it)

#set par(justify: true)

#show link: set text(fill: black)

// Setup index
#import "@preview/in-dexter:0.7.2": *

#[
  #set page(numbering: "i")
  #counter(page).update(1)

  // Preamble should not be included in the outline
  #set heading(outlined: false, supplement: none, numbering: none)

  #include "preamble/copyright.typ"
  #pagebreak()
  // Acknowledgements commented out (kept in case it is mandatory)
  // #include "preamble/acknowledgements.typ"
  // #pagebreak()
  #include "preamble/integrity.typ"
  #pagebreak()
  #include "preamble/abstract.typ"
  #pagebreak()
  #outline()
  #pagebreak()
  #outline(title: [List of Figures], target: figure.where(kind: image))
  #pagebreak()
  #outline(title: [List of Tables], target: figure.where(kind: table))
  #pagebreak()
  #outline(title: [List of Listings], target: figure.where(kind: raw))
  #pagebreak()

  = Acronyms
  #show-acronyms
  #pagebreak()

  
  = Glossary
  #show-glossary
  #pagebreak()
]

#counter(page).update(1)
#set heading(supplement: [Chapter], numbering: "1.1") // Change to [Capítulo] for Portuguese

#show figure.where(
  kind: table
): set figure.caption(position: top)

= Introduction <ch-introduction>

Modern organizations face an increasingly complex and volatile cybersecurity landscape. Cyberweapons are becoming more accessible, new vulnerabilities are disclosed daily, and digital infrastructures are growing increasingly complex and interconnected #cite(<GM19>, form: "normal"). To effectively defend against adaptive adversaries, security professionals must be capable of continuously acquiring, integrating and analyzing threat data in order to detect emerging trends and adjust defensive measures in real time.

Threat data can be categorized into quantitative metrics, including attack frequencies and exploit costs and qualitative intelligence, such as @ioc:pl and information about emerging vulnerabilities or adversarial behaviors. Organizations acquire such data from diverse external sources, such as threat intelligence feeds, @osint, public security reports and media monitoring as well as from internal systems, including @siem platforms #cite(<GM19>, form: "normal"). Nevertheless, despite the dynamic nature of this information, most threat modeling and analysis methods used in practice remain static, with limited ability to integrate and interpret continuously evolving threat intelligence #cite(<GM19>, form: "normal").

Among existing security modeling approaches, attack trees and attack graphs are well-established graphical formalisms for analyzing potential attack scenarios. They are widely employed to visualize attack paths, support security evaluations and perform quantitative risk assessments. Although the facts supplied to these models can be refreshed with updated vulnerability information or scan results, each inference execution produces a representation of the input available at that time #cite(<GM19>, form: "normal"). MulVAL can refresh vulnerability repository data and process scanner output before a new execution #cite(<MULVAL_PROJECT13>, form: "normal"), but this does not determine whether newly available information is relevant to the modeled environment, changes the attack graph structure or only affects the priority of existing paths. Separately, threat modeling outputs are not systematically translated into facts used in automated attack graph generation.

This dissertation proposes a framework that addresses these limitations. It correlates quantitative and qualitative threat intelligence with CPE based asset inventories, enabling analysis of assets for which vulnerability scans cannot be performed or are inappropriate. It translates structured threat modeling outputs into MulVAL facts, allowing adversarial assumptions identified during threat modeling to affect attack graph generation. A post-processing stage combines CVSS, EPSS, KEV status and asset criticality to score and rank the feasible paths produced by MulVAL. The resulting workflow supports repeated analysis of the same environment as relevant threat intelligence and threat modeling facts change, regenerating the graph only when the modeled attack surface changes and otherwise recalculating the risk scores and priorities of existing paths.
// - https://satoss.uni.lu/members/sjouke/papers/GM19.pdf
// - https://orbilu.uni.lu/handle/10993/41698?

== Objectives <sec-objectives>

The primary objective of this dissertation is to design and implement a dynamic framework that integrates continuously evolving threat intelligence and threat modeling with attack graphs to enhance cybersecurity modeling, situational awareness and decision making.

To achieve this goal, the dissertation pursues the following specific objectives:

1. Develop a conceptual and architectural model defining how dynamic threat intelligence (both quantitative and qualitative) and threat modeling outputs can be systematically linked to attack graphs, allowing these models to evolve in parallel with the changing threat landscape;

2. Design and implement an automated @osint acquisition and integration pipeline for collecting and normalizing threat intelligence from external sources, supporting periodic updates of the modeling environment;

3. Develop mechanisms for selective model regeneration and contextual reprioritization, so that new intelligence or threat modeling facts that change the modeled attack surface trigger a new attack graph, while updates that affect only EPSS, KEV status or asset criticality recalculate the risk scores and priorities of existing paths without structural recomputation.

4. Create post-processing, visualization and analytical components that enrich attack paths with CVSS, EPSS, KEV status and asset criticality, calculate risk scores and summarize changes in risk across successive analyses.

5. Evaluate the proposed framework through simulated case studies that examine its functional behavior, dynamic update mechanisms and analytical usefulness in representative scenarios.


== Contributions

This dissertation advances cybersecurity modeling by extending conventional attack graph snapshot analysis with a workflow that integrates evolving threat intelligence, structured threat modeling outputs and contextual risk scoring. Its contributions are summarized as follows:

1. Dynamic Integration of Threat Intelligence into Attack Models: This dissertation proposes a conceptual and architectural framework for the continuous integration of both quantitative and qualitative threat intelligence into attack graphs. The framework correlates vulnerability information with asset CPEs, providing an alternative source of vulnerability facts when scan output is unavailable, and determines whether changes in the resulting facts affect the modeled attack surface. The objective is to maintain attack representations that reflect the threat information relevant to the environment.

2. Selective Model Regeneration and Contextual Reprioritization: This work introduces a mechanism that distinguishes updates that change environment-specific vulnerability or threat modeling facts from updates that affect only their risk context. The former causes MulVAL to regenerate the attack graph, whereas the latter are handled during post-processing, which enriches the existing graph with CVSS, EPSS, KEV status and asset criticality to calculate and rank path risk scores. This distinction complements the data refresh capabilities of MulVAL adapters and avoids unnecessary graph generation when EPSS, KEV status or asset criticality changes.

3. Integration of Threat Modeling into Attack Graph Generation: This work translates structured STRIDE threat modeling outputs into logical facts compatible with MulVAL. It validates modeled assets and threat categories, maps each threat category to a MulVAL exploitation primitive and each declared impact to a consequence, allowing adversarial assumptions identified during threat modeling to participate in attack graph generation alongside vulnerability facts. This operationalizes the connection between qualitative threat modeling and automated reasoning within a reproducible pipeline.

In summary, this dissertation investigates a dynamic modeling paradigm for attack graphs within continuously changing threat environments. It aims to extend existing theoretical foundations by incorporating temporal and adaptive dimensions, while laying the basis for future research on intelligence-driven, self-evolving cybersecurity modeling.

== Structure

This dissertation is organized into six chapters that progressively build towards the proposed framework. @ch-introduction introduces the problem, motivation and objectives that guide the work. @ch-background presents the background concepts required to understand the rest of the dissertation, while @ch-state-of-the-art reviews the foundations and selected approaches to attack graph generation that are most relevant to this work. @ch-design describes the designed solution, detailing its architecture and implementation, and @ch-evaluation evaluates it through representative case studies. Finally, @ch-conclusion summarizes the main conclusions and outlines directions for future work.


= Background and Related Work <ch-background>

This chapter introduces foundational concepts of security modeling and risk analysis. It establishes the background needed to understand the work developed in @ch-state-of-the-art through @ch-conclusion.

== Security Threats and Vulnerabilities

In cybersecurity, a @threat refers to any circumstance, event or entity with the potential to cause harm to a system or its assets #cite(<ASLAN23>). Threats may arise from diverse sources, including natural events (e.g., environmental hazards affecting data centers), human actions (whether accidental or malicious) and technical failures or system malfunctions. Threats are typically characterized by their potential impact and the conditions under which they may occur #cite(<ASLAN23>), particularly when they endanger core security properties such as confidentiality, integrity and availability. 

For a threat to materialize, it must be able to leverage weaknesses within the target system. These weaknesses are known as vulnerabilities. A @vulnerability is a flaw or weakness in a system’s design, implementation, configuration or operation that can be exploited by a threat #cite(<ASLAN23>). Vulnerabilities may result from software defects, insecure configurations, architectural limitations or inadequate operational practices.

An @exploit represents the concrete mechanism through which a vulnerability is leveraged #cite(<ASLAN23>). In cybersecurity terms, exploits may take the form of software code, sequences of actions or the abuse of legitimate system functionality. They provide the practical means by which a threat is transformed into an operational action against a system. When an exploit is successfully applied, it enables an @attack, defined as a deliberate attempt to compromise a system by exploiting one or more vulnerabilities #cite(<ASLAN23>). 

== Threat Modeling Frameworks

Threat modeling frameworks are systematic and structured methodologies designed to identify, analyze and mitigate potential security threats within a system, application or process. Their primary objective is to anticipate and address security risks early in the design and development lifecycle, thereby enabling the proactive implementation of countermeasures rather than relying on reactive incident response #cite(<OWASP1>, form: "normal"). By adopting such structured approaches, organizations can gain a clearer understanding of how potential adversaries might exploit vulnerabilities to compromise critical assets, assess the likelihood and potential impact of these threats and prioritize mitigations accordingly. 

The threat modeling process typically consists of four high-level stages:
1. Defining scope and assets: Establishing the system boundaries, identifying critical assets and determining security objectives;
2. Identifying threats: Using a threat categorization methodology to systematically enumerate possible threats relevant to the system’s architecture and data flows;
3. Determining potential vulnerabilities: Analyzing how identified threats could exploit weaknesses within the system’s components or processes;
4. Proposing mitigations or controls: Defining countermeasures to eliminate or reduce identified risks. Such countermeasures can be guided by established threat countermeasure mapping lists #cite(<HERATH18>).

Once potential mitigations are identified, prioritization becomes a key consideration. Organizations may adopt different prioritization schemes based on their operational context and risk tolerance #cite(<OWASP1>, form: "normal"), balancing factors such as the likelihood of attack, potential damage and the complexity or cost of implementation.

Over the years, a variety of threat modeling frameworks have been developed to support these processes across diverse domains and levels of system complexity. Among the most widely recognized are @stride, @pasta, @octave and @vast. Each framework offers a distinct analytical perspective, ranging from technically focused, developer-oriented approaches to more strategic, business-centric methodologies. This diversity enables organizations to select, adapt or combine frameworks according to their specific architecture, security maturity and operational objectives.

// - https://owasp.org/www-community/Threat_Modeling_Process

=== STRIDE Framework

The @stride:short model, introduced by Microsoft #cite(<MS_AZ27>, form: "normal"), is a foundational framework for identifying security threats during software design and analysis. It defines six categories of potential threats, each targeting specific attack vectors that can compromise an application’s confidentiality, integrity or availability. The categories are as follows:

1. Spoofing - Spoofing is the act of forging an identity to gain unauthorized access to systems or data. Attackers impersonate trusted entities (such as users, devices or services) to deceive systems into accepting fraudulent requests. Common examples include phishing emails, fake login portals and forged network identities that trick victims or systems into revealing sensitive information or granting access #cite(<SS28>, form: "normal"); 

2. Tampering - Tampering refers to the unauthorized modification of data, configuration files or system logs. Attackers may alter data to hide their tracks, introduce vulnerabilities or manipulate system behavior for malicious purposes #cite(<SS28>, form: "normal"); 

3. Repudiation - Repudiation occurs when an actor performs an action, whether legitimate or malicious, and is later able to deny responsibility for it. It arises when a system lacks sufficient logging, tamper resistant audit trails or reliable mechanisms to bind actions to the entities that performed them, which undermines accountability and complicates forensic investigation #cite(<SS28>, form: "normal");

4. Information Disclosure - Information Disclosure refers to the exposure of sensitive or confidential information. Such leakage may result from insecure system configurations, overly verbose error messages, improperly protected storage or unsecured backups. The disclosure of this information can lead to privacy violations, regulatory non-compliance and loss of competitive advantage #cite(<SS28>, form: "normal"); 

5. @dos - Denial of Service attacks aim to disrupt the normal functioning of a service by overwhelming it with traffic or requests, thereby denying legitimate users access. These attacks can target network resources, application endpoints or backend systems #cite(<SS28>, form: "normal"); 

6. Elevation of Privilege - Elevation of privilege occurs when a user or process gains access to functionalities or data beyond their authorization. This can happen due to missing authorization checks, configuration errors or vulnerabilities in the application’s logic #cite(<SS28>, form: "normal").

// - https://www.softwaresecured.com/post/stride-threat-modelling 

Applying STRIDE involves decomposing a system into its key components, analyzing each for potential threats and implementing appropriate mitigations. This process is repeated iteratively until the remaining risks are deemed acceptable #cite(<MS_STRIDE06>, form: "normal"). 
// - https://learn.microsoft.com/en-us/archive/msdn-magazine/2006/november/uncover-security-design-flaws-using-the-stride-approach

STRIDE's structured taxonomy promotes consistency in threat identification and clear communication across teams. It is nonetheless subject to several criticisms: it focuses primarily on technical, software level threats and offers little support for capturing broader business or organizational risk, and its fixed set of six threat categories does not adapt to the particular context of each system. Despite these limitations, it remains a foundational tool in practical threat modeling #cite(<BN_STRIDE26>, form: "normal"). 
// - https://barnes.ch/cyber-STRIDE.html

=== PASTA Framework

The @pasta is a risk-centric threat modeling framework proposed by _Tony Uceda Vélez_ in 2012 #cite(<WOLF21>, form: "normal"). PASTA incorporates multiple layers of abstraction, ranging from high-level business objectives to low-level technical attack vectors.

PASTA suits systems already in operation as well as new systems still in the design phase. The framework consists of seven sequential stages, each containing multiple activities that collectively support comprehensive threat and risk analysis #cite(<WOLF21>, form: "normal"). 

The seven stages of the PASTA framework are as follows:

1. Define Objectives - This stage focuses on understanding the business context of the system. It includes identifying business objectives, defining security and compliance requirements and performing a business impact analysis to determine the potential consequences of security failures #cite(<WOLF21>, form: "normal");

2. Define Technical Scope - In this stage, the technical boundaries of the system are established. This includes capturing the scope of the technical environment and identifying infrastructure, application, software components and their dependencies #cite(<WOLF21>, form: "normal");

3. Application Decomposition - The system is broken down into its functional components to better understand how it operates. Key activities include identifying use cases, application entry points, trust levels, actors, assets, services, roles and data sources. @dfd:pl and trust boundaries are also defined during this stage #cite(<WOLF21>, form: "normal");

4. Threat Analysis - This stage identifies potential threats by analyzing probabilistic attack scenarios. It includes the analysis of security events and the correlation of threat intelligence data to better understand likely and emerging threats #cite(<WOLF21>, form: "normal");

5. Vulnerability and Weakness Analysis - Existing vulnerabilities and weaknesses are examined by querying vulnerability reports and issue tracking systems. Threats are mapped to known vulnerabilities and design flaws are analyzed through use and abuse cases. Standard scoring and classification systems such as @cvss, @cwe and @cve are used to assess severity and exposure #cite(<WOLF21>, form: "normal");

6. Attack Modeling - This stage focuses on modeling how attacks could be executed. Activities include attack surface analysis, development of attack trees (defined in detail in @sec-attack-trees-graphs), management of attack libraries (repositories of known attack patterns and techniques) and analysis of the relationship between attacks, vulnerabilities and potential exploits #cite(<WOLF21>, form: "normal");

7. Risk and Impact Analysis - The final stage evaluates and prioritizes risks by qualifying and quantifying business impact. It also involves identifying countermeasures, analyzing residual risk and defining risk mitigation strategies to reduce overall exposure #cite(<WOLF21>, form: "normal"). 

By linking business risk analysis with technical cybersecurity analysis, PASTA provides a structured method to identify, analyze and prioritize threats and risks within an application environment. This depth comes at a price, however: its seven-stage process is complex and resource-intensive, demanding considerable time, expertise and cross team collaboration, which can limit its adoption in smaller or fast-moving projects #cite(<WOLF21>, form: "normal").

=== OCTAVE Framework

@octave is a risk-focused threat modeling framework that emphasizes a deep understanding of organizational assets, associated threats and underlying vulnerabilities. Rather than concentrating solely on technical attack vectors, OCTAVE adopts an asset-centric perspective, enabling organizations to assess and manage risks in a structured and business-aligned manner #cite(<DAVIS23>, form: "normal"). By explicitly linking assets to threats and vulnerabilities, the framework supports a comprehensive understanding of organizational risk exposure.

Developed in 1999 at Carnegie Mellon University's Software Engineering Institute #cite(<HAMMAMI24>, form: "normal"), OCTAVE is designed as a comprehensive risk assessment and mitigation framework suitable for organizations of different sizes and maturity levels. The framework is particularly effective in strengthening digital business environments by aligning security practices with organizational objectives and operational realities #cite(<DAVIS23>, form: "normal"). 

The OCTAVE framework is structured around a sequence of core activities that guide analysts through systematic risk identification, evaluation, and prioritization:

1. Asset Identification: The process begins with identifying and prioritizing critical assets that require protection. This step establishes the scope of the assessment and ensures that security efforts focus on the most valuable and sensitive components of the organization #cite(<MILLER_THOMPSON22>, form: "normal").

2. Architectural Overview: An architectural analysis is performed to understand how information flows through the system. This includes identifying subsystems, data paths and trust boundaries using DFDs, providing a clear security blueprint of the application or organizational environment #cite(<DAVIS23>, form: "normal").

3. Application Decomposition: The system is examined at a granular level to uncover vulnerabilities arising from design decisions, implementation flaws and deployment configurations. This decomposition highlights potential weak points that may otherwise remain hidden #cite(<WHITE22>, form: "normal").

4. Threat Identification: Based on the identified assets and architecture, potential threat actors and threat scenarios are analyzed. This step focuses on understanding how assets could be compromised and the nature of the threats they face #cite(<BROWN_ZHAO22>, form: "normal").

5. Threat Documentation: All identified threats are systematically documented to ensure traceability, consistency and comprehensive visibility throughout the risk management process #cite(<GARCIA_JOHNSON23>, form: "normal").

6. Threat Rating and Prioritization: Threats are evaluated and prioritized using established risk classification methodologies such as CVSS and the OWASP Risk Rating Methodology #cite(<LEE22>, form: "normal"), a structured approach that estimates the severity of a risk from its likelihood and impact factors. This enables organizations to focus mitigation efforts on the most critical and high-impact risks.

OCTAVE's framework uses structured artifacts, such as asset profiles, risk flow analyses and threat mappings, to support both analytical rigor and stakeholder communication #cite(<DAVIS23>, form: "normal"). Despite its comprehensive capabilities, OCTAVE presents certain challenges. The framework requires extensive documentation, which can make its adoption resource-intensive #cite(<MILLER24>, form: "normal"). Additionally, its highly structured and methodical nature may introduce bureaucratic overhead, potentially slowing down the risk management process #cite(<MILLER24>, form: "normal"). To address these limitations, lighter-weight variants such as _OCTAVE-S_ and _OCTAVE Allegro_ #cite(<HAMMAMI24>, form: "normal") have been developed, offering streamlined alternatives better suited for smaller organizations or teams with limited risk assessment resources.

=== VAST Framework 

The @vast modeling framework is designed to enable practical, scalable threat modeling that can be continuously applied throughout the software development lifecycle. Rather than aiming for exhaustive or highly formal security models, VAST focuses on identifying actionable threats and mitigations that align with organizational risk management objectives and development workflows #cite(<HAMMAMI24>, form: "normal"). 

VAST employs two complementary and independent methodologies: application threat modeling and operational threat modeling #cite(<HAMMAMI24>, form: "normal"). Application threat modeling concentrates on identifying threats within individual applications by analyzing execution flows, trust boundaries and interaction points. Operational threat modeling addresses infrastructure-level and organizational threats, including deployment architectures, supporting services and operational processes. Together, these methodologies enable VAST to address both software-centric risks and broader operational exposures within a unified and consistent framework.

A defining characteristic of VAST is its use of @pfd:pl rather than traditional DFDs, particularly for application threat modeling #cite(<HAMMAMI24>, form: "normal"). PFDs emphasize process logic, execution paths and system interactions as they occur in practice. By prioritizing clarity and accessibility over formal completeness, VAST facilitates collaboration across development, security and operations teams while maintaining a consistent approach to threat identification and risk prioritization.

#figure(
image("images/dfdvspfd.png", width: 60%),
caption: [Comparison between a Data Flow Diagram (DFD) and a Process Flow Diagram (PFD) on a login flow],
) <fig-dfdpfd>

@fig-dfdpfd illustrates how a DFD highlights data movement and storage, whereas a process flow diagram emphasizes execution logic and decision paths within the same application scenario. The two representations therefore complement each other when analysts need to understand both information exchanges and operational behavior.

Within application threat modeling, VAST guides analysts through a structured process that includes identifying assets and entry points, analyzing potential threats, assessing their impact and defining appropriate mitigation strategies. The process-flow-based representation enhances visibility into how threats emerge across application workflows, enabling faster identification and resolution of security issues compared to more static modeling approaches #cite(<HAMMAMI24>, form: "normal").

Despite its strengths, VAST has limitations. It is not a publicly available standard and is protected by patents covering both its methodology and associated tooling #cite(<HAMMAMI24>, form: "normal"). This proprietary nature restricts its distribution, customization and adoption, particularly in open or highly regulated environments. Additionally, while VAST is effective for application threat modeling, its operational threat modeling component may be less comprehensive when compared to frameworks that place stronger emphasis on organizational or infrastructure-level risk analysis #cite(<HAMMAMI24>, form: "normal").

=== Comparison of Threat Modeling Frameworks

STRIDE, PASTA, OCTAVE and VAST each offer distinct perspectives on how threats should be identified, analyzed and mitigated. While some frameworks emphasize business risk and asset value, others focus on technical attack vectors or scalability. Understanding the strengths and limitations of each framework is essential for selecting the most appropriate approach for a given system.

@tab-threat-modeling-frameworks provides a comparative overview of the four frameworks discussed in this dissertation, highlighting their primary focus, scope, methodology, strengths and limitations. It makes the trade-offs that inform the framework selection in the following chapter explicit.

#set text(size: 9pt)

#set par(justify: false)

#figure(
  (
    table(
      columns: (0.85fr, 1.05fr, 1fr, 1.6fr, 1.25fr, 1.2fr),
      inset: 4pt,
      align: left + horizon,
      stroke: (x, y) => (
        bottom: if y == 0 { 1pt + black } else { 0.5pt + gray },
        right: if x == 0 { 1pt + black } else { 0pt },
      ),
      fill: (col, row) => if row == 0 { gray.lighten(80%) } else if col == 0 { gray.lighten(92%) },
      
      table.header(
        [*Framework*], 
        [*Focus*], 
        [*Scope*], 
        [*Method*], 
        [*Benefits*], 
        [*Limitations*], 
      ),
      
      [STRIDE], 
      [Software threats], 
      [Application], 
      [Six-category taxonomy], 
      [Simple and widely adopted], 
      [Limited business context], 
    
      [PASTA], 
      [Risk analysis], 
      [Business and technical], 
      [Seven-stage process],
      [Strong business alignment], 
      [Resource-intensive],
    
      [OCTAVE], 
      [Asset-based risk],
      [Organization and systems], 
      [Asset, threat and risk analysis], 
      [Asset and risk-focused],
      [Documentation heavy], 
    
      [VAST], 
      [Scalable threat modeling], 
      [Application and operations], 
      [Process flow modeling], 
      [Scalable and visual], 
      [Proprietary], 
    )
  ),
  caption: [Comparison of Threat Modeling Frameworks]
) <tab-threat-modeling-frameworks>

#set par(justify: true)

#set text(size: 12pt)

In summary, STRIDE serves as a foundational and accessible entry point for technical threat identification, particularly during software design. PASTA provides a comprehensive, risk driven framework that integrates business objectives with technical threat analysis, making it well suited for complex systems. OCTAVE emphasizes organizational assets and risk governance, offering a strong foundation for enterprise wide risk management. VAST, in contrast, is designed for large development environments in which scalability and rapid threat identification are important.

Selecting an appropriate threat modeling framework depends on multiple factors, including system complexity, organizational maturity, development methodology and the need to align security with business objectives. In practice, no single framework is universally sufficient, organizations often achieve more effective outcomes by selectively integrating elements from multiple approaches to address their specific technical and organizational contexts.

== Fundamentals of Attack Trees and Attack Graphs <sec-attack-trees-graphs>

=== Attack Tree

Originally introduced by _Schneier_ in 1999 #cite(<SCHNEIER99>, form: "normal"), an attack tree is a hierarchical graphical model used to represent how an adversary may exploit system vulnerabilities to achieve a specific malicious objective. The attacker’s goal is depicted as the root node, while branches represent alternative or complementary strategies that can lead to that goal. By structuring attack paths, dependencies and potential weaknesses within a single diagram, attack trees provide a systematic and visual approach to security threat modeling #cite(<MAUW_OOSTDIJK06>, form: "normal"). 
// - https://www.sciencedirect.com/science/article/pii/S0167404823005126

Attack trees support the analysis of complex systems by decomposing high-level attack objectives into progressively more detailed subgoals and concrete actions. This decomposition enables security analysts to examine potential attack strategies in a structured manner, highlighting relationships and dependencies among different attack vectors #cite(<MAUW_OOSTDIJK06>, form:"normal"). As a result, attack trees offer insight into how adversaries may realistically proceed in real-world scenarios.

Attack trees consist of three primary components: a root node representing the attacker’s main objective, intermediate nodes corresponding to subordinate goals or conditional steps, and leaf nodes that identify specific techniques, vulnerabilities or system weaknesses that can be exploited directly #cite(<MAUW_OOSTDIJK06>, form:"normal"). Logical relationships between nodes are expressed using operators such as _AND_ and _OR_, where an _AND_ relationship indicates that all connected conditions must be satisfied together and an _OR_ relationship denotes alternative paths that independently achieve the parent goal. Formally, an attack tree is a 3-tuple $(N, ->, n_0)$, where $N$ is a finite set of nodes, $->$ is a finite acyclic relation of type $-> ⊆ N times M(N)$, where $M(N)$ is the multi-set of $N$, and $n_0$ is the root node, such that every node in $N$ is reachable from $n_0$ #cite(<MAUW_OOSTDIJK06>, form:"normal"). 

As an analytical tool, attack trees facilitate proactive risk assessment by enabling security analysts to visualize possible attack pathways, identify exploitable weaknesses and evaluate the feasibility of different attack combinations. By supporting the assessment of attack likelihood, impact and dependencies, attack trees help prioritize defensive measures and contribute to informed, evidence-based decision making in cybersecurity risk management #cite(<PD24>, form: "normal").


#figure(
  //image("images/Generic-Attack-Tree-Structure-10.jpg",  width: 100%),

  image("images/attacktreeexample.png",  width: 60%),
  
  caption: [Example of an Attack Tree],
  
) <fig-attacktree>

@fig-attacktree shows an example of an attack tree. In this example, there are two distinct paths by which an attacker can achieve the ultimate goal of obtaining root access: with authentication or without authentication. In the authentication based path, the two refined options are @ssh and @rsa. Both conditions must be satisfied, as they are connected by an _AND_ operator. In contrast, the unauthenticated path requires the attacker to first obtain user-level privileges without authentication by performing the @ftp and @rsh actions. After these privileges are acquired, the attacker can exploit the local buffer overflow labeled `lobf` in the figure. This sequence is represented using a @sand operator, which is similar to an _AND_ operator but enforces a specific order in which the child actions must be carried out.

Overall, attack tree notation is both intuitive and effective for threat analysis, as it enables the systematic representation of multiple attack scenarios arising from physical and technical vulnerabilities #cite(<WIDEL19>, form: "normal"). 


=== Attack Graph

Attack graphs provide a structured representation of how cyberattacks may progress within an organization's infrastructure. By modeling systems, vulnerabilities and the dependencies between them, they expose the potential paths an adversary could exploit to compromise assets and achieve malicious objectives #cite(<LALLIE20>, form:"normal").

An attack graph is a visual model that describes the set of feasible attack paths within a networked system. Nodes represent system entities or vulnerabilities, while edges capture the actions or dependencies that allow an attacker to move between states #cite(<LALLIE20>, form:"normal"). This structure illustrates how attackers can chain exploits, move laterally and escalate privileges to reach critical resources. Formally, an attack graph is a tuple $G=(S, tau, S_0, S_s)$, where $S$ is a set of states, $tau ⊆ S times S$ is a transition relation, $S_0 ⊆ S$ is a set of initial states and $S_s ⊆ S$ is a set of success states. Intuitively, $S_s$ denotes the set of states in which the intruder has achieved their goals. Unless stated otherwise, the transition relation $tau$ is assumed to be total. An execution fragment is a finite sequence of states $s_0, s_1, ..., s_n$ such that $(s_i, s_(i+1)) in tau$ for all $0 <= i < n$. An execution fragment with $s_0 in S_0$ constitutes an execution, and an execution whose final state is in $S_s$ constitutes an attack. In other words, the execution corresponds to a sequence of atomic attacks leading to one of the intruder's goals #cite(<SHEYNER02>, form:"normal").

As an analytical tool, attack graphs enable security teams to reason about the sequence and feasibility of attacks rather than isolated vulnerabilities. They support proactive threat analysis by modeling the relationships between system components, known vulnerabilities and potential attack paths, enabling the identification of viable attack vectors #cite(<SN25>, form:"normal"). Through the evaluation and simulation of attack scenarios, organizations can prioritize mitigations, focus defensive controls and allocate resources more effectively. 

// - https://www.sentinelone.com/cybersecurity-101/cybersecurity/attack-graphs/

#figure(
  //image("images/generic-attack-graph.png",  width: 100%),
  image("images/agexample_v2.png",  width: 60%),
  caption: [Example of an Attack Graph], 
) <fig-attackgraph>

@fig-attackgraph presents an attack graph for a simple network containing a workstation, labeled WS in the figure, and a printer. State A represents an attacker with external network access to services exposed by these assets. A vulnerability on the workstation leads to State B, representing user-level access on that asset. Alternatively, a printer misconfiguration leads to State C, representing unauthorized access to the printer. From State B, a privilege escalation can lead to root access on the workstation, represented by State D. Access to the printer can also enable lateral movement to the workstation and lead to the same final state. The graph illustrates alternative attack paths and the convergence of distinct exploit sequences on a common objective.

// - https://www.sciencedirect.com/science/article/pii/S0167404823005126

=== Attack Trees vs Attack Graphs

A graph is a mathematical structure composed of nodes connected by edges and may be either directed or undirected #cite(<LALLIE20>, form: "normal"). In directed graphs, edges indicate transitions from a source node to a destination node, whereas undirected graphs represent bidirectional relationships without an inherent direction.

A tree is a specialized type of Directed Acyclic Graph (DAG) with a strict hierarchical structure #cite(<MAUW_OOSTDIJK06>, form: "normal"). It consists of a single root node, internal nodes with one parent and one or more children and leaf nodes with no children. This structure enforces a clear decomposition of objectives and explicitly prohibits cycles.

These structural differences directly influence how attack trees and attack graphs represent adversarial behavior. Attack trees are acyclic by definition and are centered around a single attacker goal, represented by the root node. They decompose this goal into subgoals and atomic attack steps arranged hierarchically. Attack trees typically express attack logic in a bottom-up manner, combining individual exploits to reach the final objective. In most formulations, nodes represent exploits, while the satisfaction of preconditions is assumed implicitly during transitions. Attack graphs, in contrast, offer a more expressive modeling framework. They may include multiple goal states and allow cycles, enabling the representation of repeated or looping actions and evolving attack strategies. Attack graphs commonly represent attack progression in a state based manner and explicitly model both exploits and the preconditions that enable them. This allows for a detailed representation of intermediate system states, partial attacks and alternative execution paths #cite(<LALLIE20>, form: "normal"). 

While both approaches use graph-based structures to model attack behavior, they differ in expressive power, treatment of preconditions and representation of attack progression. Because attack trees organize a single objective into a clear hierarchy of subgoals while leaving preconditions implicit, they are well suited for high-level, goal-oriented analysis and for communicating attack logic to stakeholders. Attack graphs, by explicitly modeling system states, exploit preconditions and the dependencies between steps, and by allowing multiple goals and cycles, capture how the many steps of complex, multi-stage attacks interact, which makes them more appropriate for detailed technical modeling.

== Vulnerability Databases and Classification Systems

Vulnerability databases and classification systems provide structured repositories of information about known security weaknesses, supporting vulnerability management, risk assessment and security analysis. By standardizing the identification and description of vulnerabilities across software, hardware and networked systems, these resources facilitate information sharing and serve as key inputs to security assessment methodologies and analytical models.


=== CVE (Common Vulnerabilities and Exposures)

@cve#footnote[https://www.cve.org] is a publicly accessible catalog of disclosed cybersecurity vulnerabilities. The CVE system was created in 1999 by the MITRE Corporation #cite(<RH_CVE24>, form: "normal"), a U.S. government funded research and development organization, to establish a standardized method for reporting and tracking software vulnerabilities. Each CVE entry provides a brief description of the issue, but does not include in depth technical details, risk assessments or remediation steps. Those elements are documented in complementary databases such as the U.S. @nvd #footnote[https://nvd.nist.gov/vuln] and various vendor maintained advisory lists.

Despite these different sources, the CVE ID serves as a consistent reference point, enabling security teams, vendors and researchers to coordinate vulnerability analysis, compare data and develop tools and mitigation measures #cite(<RH_CVE24>, form: "normal"). While MITRE maintains the CVE list, entries are often submitted by vendors, security researchers and members of the open-source community. 

// *Criteria for Assigning a CVE ID*

According to @cna operational rules, a vulnerability must meet specific conditions to receive a CVE ID:

1. Independently fixable: The vulnerability must be remediable without requiring changes to other unrelated issues #cite(<RH_CVE24>, form: "normal");

2. Acknowledged or demonstrably impactful: The affected vendor must acknowledge the flaw and confirm its security impact or the reporter must provide a detailed vulnerability report demonstrating both the security impact and its violation of the system’s security policy #cite(<RH_CVE24>, form: "normal");

3. Affects a single codebase: Each affected codebase is assigned its own CVE. When several products share the same flawed library, protocol or standard, a single CVE is used only if every implementation is inherently affected by that flaw. Otherwise, each affected product or codebase receives a separate CVE entry #cite(<RH_CVE24>, form: "normal").

// -- https://www.redhat.com/en/topics/security/what-is-cve

// *Assessing Vulnerability Severity*

Vulnerabilities are evaluated based on their severity, and several frameworks exist to support this assessment. The most widely adopted is the @cvss, which assigns a numerical score ranging from 0.0 to 10.0 according to a vulnerability’s exploitability, impact and environmental characteristics #cite(<IBM_CVSS24>, form: "normal"). Higher scores correspond to greater potential risk. CVSS is used by the NVD and many security vendors #cite(<IBM_CVSS24>, form: "normal"), although some organizations complement it with proprietary or context-specific scoring methodologies.

Beyond providing a numerical score, CVSS is central to modern vulnerability management, helping organizations prioritize which security issues to address first. Over time, several CVSS versions have been released. The latest, CVSS 4.0, refines how severity is assessed to better support real-world risk decisions #cite(<IBM_CVSS24>, form: "normal").

CVSS 4.0 organizes vulnerability characteristics into four metric groups #cite(<IBM_CVSS24>, form: "normal"). Together, these groups provide a more comprehensive view of vulnerability severity by incorporating both technical and contextual factors:
- Base - Intrinsic qualities of a vulnerability (e.g., ease of exploitation and potential impact on confidentiality, integrity and availability);
- Threat - Factors that change over time, such as the availability of exploit code or evidence of active attacks;
- Environmental - Adjustments that reflect how critical the affected asset is in a specific organization’s environment;
- Supplemental - Additional context beyond technical severity, such as ease of automation or potential safety implications.

// - https://www.ibm.com/think/topics/cvss

Despite the release of CVSS 4.0, CVSS v3.x (most commonly v3.0 or v3.1) remains the predominant version used in practice. Many tools, databases and workflows continue to rely on CVSS v3 due to its widespread adoption and ecosystem support #cite(<FIRST_CVSS30>, form: "normal").

CVSS v3.x centers on the Base Score, which captures the inherent severity of a vulnerability using the following metrics: Attack Vector (AV), Attack Complexity (AC), Privileges Required (PR), User Interaction (UI), Scope (S), Confidentiality Impact (C), Integrity Impact (I) and Availability Impact (A) #cite(<FIRST_CVSS30>, form: "normal"). These metrics collectively describe how a vulnerability can be exploited and the extent of its potential impact, forming the foundation for severity-based vulnerability prioritization.

// - https://www.first.org/cvss/calculator/3.0


=== CWE (Common Weakness Enumeration) 

The @cwe#footnote[https://cwe.mitre.org] is a community maintained catalog of common software and hardware weaknesses #cite(<MITRE_CWE24>, form: "normal"). A weakness refers to a design or implementation flaw that may lead to a security vulnerability when exploited under specific conditions. CWE provides a standardized taxonomy for describing and classifying such weaknesses, enabling consistent communication about the root causes of security flaws across tools, organizations and development teams #cite(<MITRE_CWE24>, form: "normal").

Unlike vulnerability databases that document specific, observed flaws, CWE focuses on generalized patterns of error that recur across systems and technologies. For example, CWE-79 (Improper Neutralization of Input During Web Page Generation) describes the underlying weakness that can result in @xss vulnerabilities #cite(<MITRE_CWE24>, form: "normal"). Multiple CVEs may reference CWE-79, indicating that distinct vulnerabilities share the same fundamental cause.

By abstracting individual vulnerabilities to their underlying weaknesses, CWE enables a more proactive approach to security improvement. Developers can use CWE to guide secure coding practices, architects can identify design-level risks and security teams can use CWE classifications to identify recurring weakness patterns across applications. This allows organizations to address the root causes of vulnerabilities through improved design decisions, coding standards and development processes, rather than repeatedly patching individual flaws #cite(<INTR_CWE>, form: "normal").

=== CPE (Common Platform Enumeration)

@cpe#footnote[https://nvd.nist.gov/products/cpe] is a standardized naming scheme used to uniquely identify information technology products, including operating systems, applications and hardware devices #cite(<NISTIR7695>, form: "normal"). A CPE name provides a structured and unambiguous way to describe a specific product and its version, enabling consistent reference to the same platform across different security tools, databases and organizations.

CPE names follow a formal specification derived from the generic syntax of @uri:pl #cite(<NISTIR7695>, form: "normal"), which allows them to be reliably interpreted and used in automated security analysis and vulnerability management workflows. For example:

``` cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*```

This CPE uniquely identifies version 2.4.49 of the Apache HTTP Server. In this string, 2.3 indicates the CPE specification version, the part field `a` denotes an application (the other possible values being `o` for operating systems and `h` for hardware), and the wildcard fields (\*) specify that the identifier applies regardless of update, edition, language or platform. Vulnerabilities referencing this CPE can be automatically matched to systems running the affected software, independent of variations in local inventories or vendor documentation.

The Official CPE Dictionary is a publicly available repository containing an authoritative list of standardized CPE names. Each entry represents a specific product release and serves as a common reference for vulnerability databases, scanners, and security assessment tools #cite(<NISTIR7695>, form: "normal"). The dictionary is maintained as a living resource, regularly updated with new releases and corrections, ensuring that CPE remains a reliable foundation for automated vulnerability identification and correlation.

=== Limitations of Severity-Based Vulnerability Scoring

The CVSS is widely used to assess the potential severity of software vulnerabilities. However, CVSS scores do not capture how likely a vulnerability is to be exploited in real-world attacks. This limitation has significant implications for vulnerability management, where effective prioritization depends not only on potential impact but also on the probability of exploitation #cite(<JAC_ROM21>, form:"normal").

Empirical studies consistently demonstrate the shortcomings of severity-based prioritization: only a small fraction of disclosed vulnerabilities are ever exploited, with some studies reporting exploitation rates as low as 1.4% #cite(<JAC_ROM21>, form:"normal"). Moreover, remediation strategies based solely on CVSS severity have been shown to perform poorly when evaluated against actual attacker behavior, offering little improvement over random selection when the objective is to reduce exposure to exploited vulnerabilities #cite(<JAC_ROM21>, form:"normal"). These findings highlight the need for complementary approaches that explicitly incorporate exploitation likelihood and observed attacker activity.

==== EPSS (Exploit Prediction Scoring System)

The @epss#footnote[https://www.first.org/epss/] was developed to address this need by estimating the probability that a vulnerability will be exploited within a defined period following public disclosure. EPSS is a predictive, data-driven model that produces a continuous probability score between 0 and 1, where lower values indicate a minimal likelihood of exploitation and higher values indicate increased risk #cite(<JAC_ROM21>, form:"normal").

This score is derived from a binary prediction task: whether a vulnerability is exploited in the wild within 12 months of disclosure. EPSS models this outcome using standard logistic regression, selected for its balance between predictive performance, interpretability and computational efficiency #cite(<JAC_ROM21>, form:"normal"). The resulting coefficients can additionally be interpreted as changes in odds ratios, enabling analysts to understand the influence of different predictors #cite(<JAC_ROM21>, form:"normal").

The result is an interpretable scoring system that focuses on exploitation probability rather than severity alone. A key advantage of EPSS is its ability to generate probability estimates immediately upon vulnerability disclosure, enabling early prioritization without reliance on confirmed exploit activity #cite(<JAC_ROM21>, form:"normal"). As new exploit and threat intelligence becomes available, the model can be updated to reflect evolving attacker behavior.

In practice, EPSS complements CVSS by introducing a predictive threat dimension to vulnerability assessment. While CVSS characterizes potential impact, EPSS supports more effective risk reduction by helping security teams prioritize vulnerabilities that are most likely to be exploited, thereby improving the allocation of limited remediation resources. 

==== KEV (Known Exploited Vulnerabilities)

While EPSS provides a predictive estimate of future exploitation likelihood, the @kev catalog, maintained by the @cisa#footnote[https://www.cisa.gov/known-exploited-vulnerabilities-catalog], supports vulnerability prioritization based on observed rather than predicted threat activity #cite(<CISA_KEV26>, form: "normal"). The catalog serves as an authoritative reference of vulnerabilities that have been confirmed to be exploited in the wild, offering directly actionable intelligence for security teams #cite(<CISA_KEV26>, form: "normal"). Consequently, organizations are encouraged to incorporate KEV as a primary input to remediation planning, ensuring that vulnerabilities associated with demonstrated attacker behavior receive priority attention.

Unlike scoring systems such as CVSS, inclusion in the KEV catalog is not based on theoretical severity or exploit complexity. Instead, the primary criterion for inclusion is reliable evidence that a vulnerability has been, or is being, exploited in the wild #cite(<CISA_KEV26>, form: "normal"). In the context of the KEV catalog, the terms “exploited” and “actively exploited” are used interchangeably to describe confirmed cases in which malicious actors have successfully executed code against a vulnerable system without authorization from the system owner #cite(<CISA_KEV26>, form: "normal"). 

By emphasizing observed exploitation rather than hypothetical risk, KEV provides an important corrective to purely score based prioritization. For example, a vulnerability with a moderate CVSS score may warrant immediate remediation if it appears in the KEV catalog, while a higher scoring vulnerability without known exploitation may be addressed with lower urgency.

== Open-Source Intelligence (OSINT) 

OSINT refers to the process of collecting, evaluating, and analyzing publicly available information in order to produce actionable intelligence that answers a specific question or supports a defined objective #cite(<SANS_OSINT26>, form:"normal"). To understand OSINT, it is essential to distinguish between information and intelligence. Information alone consists of raw and unprocessed data, it becomes intelligence only after it has been critically assessed, contextualized and analyzed to generate insight or understanding. In other words, intelligence is the result of transforming unstructured or fragmented data into meaningful conclusions that can inform and guide decision making #cite(<SANS_OSINT26>, form:"normal").

// *Types of OSINT Collection* 

There are two primary categories of OSINT collection: passive and active.

- Passive OSINT refers to the process of gathering information without directly interacting with a target, for example through publicly available sources such as vulnerability databases, social media content or archived web pages. Passive collection minimizes the risk of exposure and maintains a non intrusive approach;

- Active OSINT, in contrast, involves some degree of interaction with the target, such as querying publicly exposed services or enumerating domain-related information. This form of collection can resemble investigative or undercover activities and depending on organizational policies, may require prior authorization or ethical review before engagement.

// *Applications of OSINT*

// OSINT has a broad range of applications, including market intelligence, competitive analysis, academic research and policy development #cite(<SANS_OSINT26>, form:"normal"). Within the domains of security and intelligence, it plays a particularly vital role. By systematically collecting and analyzing open-source data, intelligence professionals can identify potential threats such as cyberattacks, detect emerging patterns and monitor adversarial activities. These capabilities support the development of proactive strategies aimed at mitigating evolving risks before they materialize.

In summary, OSINT serves as a powerful and ethically grounded means of collecting and interpreting publicly available data. When applied responsibly and in accordance with legal and professional standards, OSINT enables organizations and individuals to make informed, data-driven decisions across a wide range of operational and strategic contexts.

// - https://www.sans.org/blog/what-is-open-source-intelligence


== Cyber Threat Intelligence (CTI)

The term @cti is often intuitively misunderstood, because it does not lend itself to a single, universally accepted definition #cite(<LEE_CTI23>, form: "normal"). To define CTI clearly, it is necessary to examine the two constituent concepts: intelligence and cyber threat. As discussed in the previous sections, intelligence refers to evidence-based knowledge that reduces uncertainty and supports informed decision making. A cyber threat, in turn, denotes any potential or actual malicious activity enabled through digital systems that may compromise the confidentiality, integrity or availability of information and services. CTI can therefore be understood as the provision of structured and contextualized insight that enables organizations to comprehend adversaries, anticipate their actions and implement effective defensive measures #cite(<MAV_BRO17>, form: "normal").
// - Cyber Threat Intelligence - Por Martin Lee

// - Cyber Threat Intelligence Model: An Evaluation of Taxonomies, Sharing Standards, and Ontologies within Cyber Threat Intelligence Publisher: IEEE - Vasileios Mavroeidis and Siri Bromander

CTI is closely related to OSINT, but the two terms are not equivalent. OSINT transforms publicly available information into intelligence for a defined purpose, whereas CTI applies intelligence processes specifically to cyber threats and cyber defense #cite(<SANS_OSINT26>, form:"normal") #cite(<MAV_BRO17>, form:"normal"). CTI may use OSINT alongside internal telemetry, commercial reporting and other sources. Thus, OSINT can contribute to CTI, but not all OSINT concerns cybersecurity and CTI is not limited to publicly available information.

=== STIX

@stix is an open, standardized language for representing and exchanging cyber threat intelligence in a machine-readable and interoperable format. It is developed by the @oasis, an international standards body responsible for widely adopted specifications for information exchange. STIX defines a common data model for describing cyber threat entities, such as threat actors, malware, attack techniques, vulnerabilities, indicators and observed incidents, and the relationships between them #cite(<OASIS_STIX_INTRO26>).

A key advantage of STIX over unstructured threat reports is its ability to preserve analytical context. Rather than sharing isolated indicators, STIX represents intelligence as interconnected objects that reflect real-world relationships between adversaries, infrastructure and behaviors. This structured representation enables automated processing, correlation across data sources and integration with security platforms, thereby aligning technical exchange with the analytical objectives of CTI #cite(<OASIS_STIX_INTRO26>). In this way, STIX acts as a foundational enabler of large-scale intelligence sharing and collaborative defense.

STIX 2.x, the current generation of the standard, represents these objects in JSON, so that each models a distinct concept in the threat landscape and can be linked to others to form a coherent intelligence picture. A representative STIX 2.1 Campaign object is reproduced in @app-stix-example.

// -- https://oasis-open.github.io/cti-documentation/stix/intro.html

== Asset Criticality and Risk Assessment

Effective risk assessment requires more than identifying vulnerabilities and estimating their likelihood of exploitation, it must also account for the value and operational importance of the assets affected. Asset criticality provides this business context, allowing the consequences of a successful attack to be incorporated into the prioritization of security measures.

=== Asset Criticality Assessment

Asset criticality assessment is the process of identifying and evaluating the importance of system components with respect to an organization’s mission, operations and overall security posture #cite(<NIST_SP80030R1>). The assessment establishes which assets are most valuable, most sensitive or most essential to operational continuity, providing a foundation for subsequent risk assessment and prioritization of security measures.

The first step in asset criticality assessment is to systematically identify all relevant assets within the system or environment under consideration #cite(<NIST_SP80030R1>). This includes hardware components such as servers, network devices and storage systems, software assets including applications, services and operating systems, and information and data assets such as databases, configuration files, sensitive documents and proprietary information. The assessment must also consider users and digital identities, such as privileged accounts and roles with access to critical resources, as well as business processes and services that rely on IT systems to ensure continuity and operational performance.

Once assets are identified, their criticality is evaluated based on criteria that reflect the potential consequences of compromise. Common criteria include #cite(<NIST_SP80030R1>):

- Confidentiality Impact: The severity of consequences if unauthorized disclosure occurs;

- Integrity Impact: The potential harm from unauthorized modification or corruption of the asset;

- Availability Impact: The operational and business impact if the asset becomes unavailable;

- Business Impact: Financial loss, legal exposure, regulatory compliance issues and reputational damage;

- Dependency and Inter-connectivity: The degree to which other assets, services or processes depend on the asset in question.

By quantifying the importance of assets, criticality assessment provides a basis for estimating the impact component of risk. High criticality assets amplify the consequences of successful attacks, guiding analysts to prioritize mitigation strategies for these assets. When combined with likelihood estimations derived from vulnerabilities and attack modeling, asset criticality forms a core component of a structured risk assessment framework.

=== Risk Assessment Methodologies

Risk assessment provides a systematic means of evaluating the security posture of a system by estimating the potential consequences of successful attacks. It combines information about threats, vulnerabilities and assets to support prioritization and decision making. Within this process, asset criticality determines the impact dimension of risk, while the likelihood of exploitation must be estimated through appropriate analytical methods. Approaches for this estimation differ in their level of formality, required input data, and degree of automation.

Qualitative methods estimate likelihood and impact through expert judgment and descriptive scales. Techniques such as likelihood impact matrices and scenario based analysis allow organizations to reason about risk even when detailed technical data are unavailable. These methods are easy to apply and to communicate, but because they depend on subjective judgment, different analysts or organizations may reach different conclusions about the same risk.

Quantitative and semi-quantitative methods seek to express likelihood and impact numerically in order to compare risks more precisely. Scoring schemes such as CVSS, as well as probabilistic models, represent attempts to approximate the likelihood component of risk in a repeatable manner. However, these approaches often rely on simplifying assumptions and may not fully capture complex attack dependencies or adversary behavior.

Model-based methods address this limitation by deriving likelihood estimates from structured representations of the system, such as attack graphs or attack trees. In these models, the probability of compromise can be inferred from properties including attack path length, reachability of critical assets and required attacker capabilities. By weighting model elements according to asset criticality, these approaches directly connect the technical structure of attacks with the business impact dimension of risk.

However, the quality of these estimates ultimately depends on how the attack model itself is generated. The literature identifies three model construction approaches #cite(<KM23>, form: "normal"):

==== Model-Driven Approaches

Model-driven approaches begin with a structured description of the system and apply predefined transformation rules to generate an attack model #cite(<KM23>, form: "normal"). The input may take the form of architectural diagrams, configuration specifications or dedicated security modeling languages. Because these descriptions are typically formulated to capture threats or attacker capabilities, the transformation process does not require detailed vulnerability analysis. In some cases, the initial representation already resembles an attack model or a closely related threat model.

The primary strength of model-driven approaches lies in their systematic and largely automated construction of the attack model. However, the realism of the resulting attack models depends heavily on the accuracy and completeness of the input description. When this abstraction diverges from the actual security posture of the system, important attack paths may be missed #cite(<KM23>, form: "normal").

==== Analysis-Driven Approaches

Analysis-driven approaches construct attack models through explicit reasoning over available information about the system #cite(<KM23>, form: "normal"). The starting point is a system description that may be enriched with formal security properties, design constraints or data from vulnerability repositories. Analytical procedures then derive intermediate results that are translated into feasible attack scenarios.

Methods in this category vary with respect to the abstraction level of the system model, the formalisms used to express threats and the analysis techniques employed. Techniques range from basic reachability analysis in graphs to more advanced methods based on model checking, constraint satisfaction or automated planning. Threats are typically specified using formal or semi-formal languages, and the analysis extracts attack paths that are summarized in the resulting model #cite(<KM23>, form: "normal").

==== Vulnerability-Driven Approaches

Vulnerability-driven approaches focus on known weaknesses and attempt to instantiate attack models by matching vulnerability patterns against available system information #cite(<KM23>, form: "normal"). The required level of knowledge varies: some methods assume detailed inventories of network topology and installed software, while others rely on logs or expert input.

Vulnerability patterns are commonly represented as fragments of attack trees or graphs that refine or extend an existing model. Implementations range from semi-automatic techniques requiring analyst guidance to fully automated processes. These methods are particularly effective when comprehensive and up-to-date vulnerability data are available, yet their coverage is inherently limited by the completeness and accuracy of those sources.

While the approaches discussed above derive risk estimates from explicit system and attack models, not all security assessments can rely on such detailed representations. In many practical settings, particularly during early design phases or exploratory threat modeling, analysts must reason about risk before architectural models or comprehensive vulnerability data are available. In these contexts, structured scoring frameworks are commonly employed to support comparative prioritization rather than precise estimation.

=== DREAD Framework

Unlike the model-driven, analysis-driven and vulnerability-driven approaches described above, @dread:short does not attempt to represent attack paths, dependencies or system structure explicitly. Instead, it evaluates individual threats through an ordinal scoring scheme that approximates both impact and likelihood-based on expert judgment. DREAD is therefore best understood as a threat prioritization mechanism rather than a comprehensive risk modeling technique.

The DREAD framework is a quantitative risk rating model proposed by Microsoft to support the prioritization of identified security threats #cite(<SHEIKH_SIN23>). Unlike threat modeling approaches that focus primarily on threat discovery, DREAD is applied after threats have been identified to assess their relative risk and determine which threats require immediate mitigation. This prioritization is essential in practical security engineering, where time, budget and personnel constraints make it infeasible to address all identified threats simultaneously.

DREAD evaluates risk by scoring threats across five dimensions: Damage, Reproducibility, Exploitability, Affected Users, and Discoverability. Each dimension captures a different aspect of threat severity and likelihood, providing a structured and repeatable method for comparing heterogeneous threats.

- Damage refers to the potential impact of a successful attack, including financial loss, service disruption, data compromise or reputational harm;

- Reproducibility measures how consistently an attack can be reproduced once discovered, reflecting the effort required to repeat the exploit;

- Exploitability assesses how easy it is to launch the attack, considering factors such as required skill level, tool availability and access prerequisites;

- Affected Users represents the proportion of users, systems or stakeholders impacted if the threat is realized;

- Discoverability indicates how easily an attacker can identify the vulnerability or attack vector, either through system observation, documentation or automated scanning.

Each category is assigned a numerical score reflecting its severity. The scoring scheme employs a three point ordinal scale, where values of 1, 2 and 3 correspond to low, medium and high risk respectively, with 0 indicating the absence of risk #cite(<KIM_KIM22>). The overall risk score is then calculated by summing the individual category scores #cite(<SHEIKH_SIN23>):

$ "Risk Score" = D + R + E + A + D $

The resulting score ranges from 0 to 15, where higher values indicate greater risk exposure. Based on the total score, threats are commonly classified into qualitative risk levels, such as low (0-6), medium (7-11) and high (12-15), enabling security teams to prioritize mitigation efforts accordingly #cite(<SHEIKH_SIN23>). 

@dread's primary strength lies in its simplicity and ease of integration with other threat modeling techniques. When used in conjunction with frameworks such as @stride:short or attack tree analysis, @dread:short provides a pragmatic mechanism for translating identified threats into actionable risk priorities #cite(<SHEIKH_SIN23>). However, the framework has notable limitations. The scoring process remains partially subjective and may vary between assessors, particularly in the absence of clear scoring guidelines. Additionally, @dread:short does not explicitly account for business context, threat actor intent or evolving risk over time, which can limit its effectiveness in complex or highly dynamic environments #cite(<SS_COMPARISON23>). 

Despite these limitations, DREAD remains a widely referenced and practical risk assessment technique, particularly suited for early stage design analysis and comparative threat prioritization within application-centric security assessments #cite(<KIM_KIM22>). It is most useful when its subjective scores are supported by complementary technical and contextual evidence.

== Chapter Summary

This chapter established the foundations required to reason about dynamic attack graph generation. It introduced security threats and vulnerabilities, compared the principal threat modeling frameworks, distinguished attack trees from attack graphs, and examined the vulnerability and threat intelligence standards that describe software exposure. It also discussed asset criticality, risk assessment methodologies and the limits of severity-only prioritization, motivating the use of exploitation likelihood and contextual risk signals.

These concepts provide the vocabulary and analytical basis for the remainder of the dissertation. The next chapter examines the foundations and selected approaches to attack graph generation, comparing the representations and tools most relevant to the proposed framework.


= Foundations and Selected Approaches to Attack Graph Generation <ch-state-of-the-art>

Building on the concepts introduced in @ch-background, this chapter reviews foundational attack graph representations and selected tools relevant to this dissertation. It first surveys historically influential representations and the tools developed to construct them automatically, and then examines in greater depth the three systems most relevant to this dissertation, namely MulVAL#footnote[https://github.com/risksense/mulval?tab=readme-ov-file], SeaMonster#footnote[https://sourceforge.net/projects/seamonster/] and @sage#footnote[https://github.com/tudelft-cda-lab/SAGE], before comparing their respective strengths, limitations and suitability as a foundation for the proposed framework.

== Attack Graphs

As previously established, an @ag is a modeling formalism used to represent the sequences of actions that may lead to a successful cyberattack. Over the past two decades, numerous AG representations and automated generation techniques have been proposed to support security analysis and decision making #cite(<TAY_BAU23>, form: "normal"). This section reviews the historically influential AG frameworks relevant to this dissertation: @at:pl, @sg:pl, @edg:pl, @lag:pl, @bag:pl and @mpag:pl. It then outlines the principal tools developed for their automated construction. @fig-ag-evolution illustrates the chronological evolution of these representations and their associated toolchains, highlighting their historical development and influence within cybersecurity research #cite(<TAY_BAU23>, form: "normal").

#figure(
  
  image("images/evolutionagrep.png",  width: 100%),
  caption: [Evolution of AG Representations],
) <fig-ag-evolution>


The diversity of attack graph representations reflects the wide range of domains in which they have been applied. The data summarized in @fig-ag-evolution is based on studies available up to 2021 and is therefore used here as a historical overview rather than as a description of the current state of the field. More recent representations and tools may not be reflected in the distribution. Within its period of coverage, the figure indicates the prominent role of ATs and SGs and the established position of @mulval among AG generation tools.

=== Attack Tree (AT)

Attack trees are an early, widely adopted approach to security threat modeling #cite(<SCHNEIER99>, form: "normal"). Their conceptual foundations, strengths and limitations were presented in @sec-attack-trees-graphs. @seamonster is an open-source security modeling tool that uses attack trees to relate vulnerabilities, attack paths and countermeasures throughout the software development lifecycle #cite(<MELAND08>, form: "normal").

=== State Graph (SG)

The SG representation, introduced with the Attack Graph Toolkit#footnote[https://www.cs.cmu.edu/~scenariograph/] in 2002, is an early formal approach to attack graph modeling #cite(<SHEYNER02>, form: "normal"). Nodes represent global system states, while edges represent attacker actions that transition between them. This captures multi-step attack dynamics. However, explicit enumeration of states and transitions leads to the _#gls("statespaceexplosion")_ problem #cite(<SHEYNER02>, form: "normal"). As hosts and vulnerabilities increase, the number of global states grows exponentially, making enumeration infeasible for realistic environments.

The @monotonicity mitigates this limitation #cite(<AMMANN02>, form: "normal"). It assumes that an attack step does not invalidate other preconditions, so satisfied conditions remain valid. Under this constraint, attack graph generation complexity can be reduced from exponential to polynomial, enabling analysis of larger systems.

=== Exploit Dependency Graph (EDG)

The EDG, introduced in 2003 #cite(<NOEL03>, form: "normal"), enumerates exploit sequences under the monotonicity assumption. Each exploit and dependency appears once, and only exploits contributing to the attacker’s objective are included. This reduces redundancy, yielding a graph whose size grows quadratically with the number of exploits and scales better than full state enumeration. EDG construction can nevertheless remain demanding in large environments #cite(<NOEL03>, form: "normal").

The @tva approach generates the graph backward from the attacker’s goal, using exploit and condition nodes to identify paths relevant to compromise #cite(<JAJODIA07>, form: "normal"). Cauldron, an enterprise TVA implementation, adds visualization, vulnerability data integration and automated mitigation recommendations #cite(<JAJODIA11>, form: "normal"). @fig-edg illustrates a representative EDG, where exploit and condition nodes express the prerequisites and dependencies leading to the attacker’s objective.

#figure(
  
  image("images/edggraph.png",  width: 45%),
  caption: [Example of EDG],
) <fig-edg>


=== Logical Attack Graph (LAG)

The LAG, introduced in 2005 #cite(<OU06>, form: "normal"), represents attack scenarios as a directed graph that can be structured as a tree. With the monotonicity assumption, its size grows polynomially with the number of exploits, enabling more scalable analysis than state enumeration #cite(<OU06>, form: "normal").

Logical inference generates LAGs from formal rules expressing attack preconditions and effects. Tools such as MulVAL combine system configuration and vulnerability data to derive feasible attack paths #cite(<OU06>, form: "normal").


=== Bayesian Attack Graph (BAG)

BAGs model attack progression as a directed acyclic graph in which nodes represent security states and edges encode probabilistic dependencies between them. By associating nodes with conditional probability tables, BAGs enable quantitative reasoning about the likelihood of compromise and support risk assessment through Bayesian inference #cite(<LIU_MAN05>, form: "normal"), whereby the probability of system compromise is derived by propagating uncertainties along the attack graph and revised as new evidence is observed. This approach allows analysts to update the estimated probability of attack success whenever new evidence (such as alerts, vulnerability disclosures or observed exploits) becomes available.

Despite their strong analytical capabilities, BAGs remain less common in practice due to the difficulty of obtaining reliable probability estimates and the absence of widely adopted automated generation tools #cite(<TAY_BAU23>, form: "normal"). @fig-bag illustrates a typical BAG, where the directed structure expresses conditional relationships between attack steps and the associated probabilities used for inference.

#figure(  
  image("images/bagraph.png",  width: 50%),
  caption: [Example of BAG],
) <fig-bag>

=== Multiple Prerequisite Attack Graph (MPAG)


The MPAG, introduced in 2006 #cite(<INGOLS06>, form: "normal"), extends exploit dependency models by representing prerequisites shared by multiple exploits. It employs state nodes for attacker access on a host, prerequisite nodes for conditions such as network reachability or credentials, and vulnerability nodes for exploited vulnerabilities. Aggregating prerequisites across attack paths reduces the number of edges and improves scalability.

NetSPA and its commercial derivative FireMon#footnote[https://www.firemon.com/] implement MPAGs for vulnerability prioritization and mitigation planning #cite(<ARTZ02>, form: "normal"). @fig-mpag illustrates a representative MPAG, where distinct node types show how conditions are reused across attack steps. Numerous cyclic dependencies can nevertheless make large MPAGs difficult to interpret #cite(<INGOLS06>, form: "normal").

#figure(
  image("images/mpagexample2.png",  width: 70%),
  caption: [Example of MPAG],
) <fig-mpag>


=== Complementary Attack Graph Frameworks

In addition to the frameworks discussed above, other attack graph generation tools are used in practice. Skybox View, introduced in 2005, is a commercial platform for vulnerability and threat management whose proprietary attack graph representation supports vulnerability assessment and remediation workflows #cite(<TAY_BAU23>, form: "normal"). CySeMoL#footnote[https://www.kth.se/nse/research/software-systems-architecture-and-security/projects/old-projects/cysemol/downloads-1.432383] provides a modeling language and toolset for estimating enterprise cybersecurity through quantitative attack and defense relationships while requiring limited security expertise #cite(<HOLM13>, form: "normal"). MITRE’s CyGraph#footnote[https://www.mitre.org/our-impact/intellectual-property/cygraph], introduced in 2016, combines TVA-based network modeling with layers for cyber threats and mission dependencies #cite(<NOEL16>, form: "normal"). More recently, CTI-driven approaches, such as SAGE #cite(<NADEEM22>, form: "normal") and AttacKG#footnote[https://github.com/li-zhenyuan/AttacKG] #cite(<LI21>, form: "normal"), construct attack graphs from cyber threat intelligence rather than solely from system vulnerabilities. DeepAG further combines attack graph techniques with deep learning for prediction and prioritization #cite(<LI23>, form: "normal").

Despite these advances, attack graph generation continues to face scalability and visualization challenges in large environments #cite(<LALLIE20>, form: "normal"). @tab-attack-graph-tools compares the tools by accessibility, representation, generation complexity and analyst usability. In this comparison, generation complexity refers to the expected asymptotic growth in the computational cost of constructing an attack graph as the size of the input model increases. Depending on the representation, input size may be measured by hosts, vulnerabilities, exploits, prerequisites or reachable states. The asymptotic expressions therefore identify each approach's principal scalability limitation rather than apply a common definition of $N$.

#set text(size: 10pt)
#set par(justify: false)

#figure(
  table(
    inset: 7pt,
    align: left + horizon,
    stroke: (x, y) => if y == 0 { (bottom: 1.5pt + black) } else { (bottom: 0.5pt + silver) },
    fill: (col, row) => if row == 0 { luma(240) },

    columns: (auto, auto, auto, auto, auto),
    table.header(
      [*Tool*], [*Accessibility*], [*AG Representation*], [*Generation Complexity*], [*Usability*],
    ),

    [Attack Graph Toolkit], [Open-source], [State Graph (SG)], [$O(2^N)$], [Moderate],

    [MulVAL], [Open-source], [Logical AG (LAG)], [$O(N^2) - O(N^3)$], [High],

    [TVA], [Restricted / not publicly available], [EDG], [$O(N^3)$], [High],

    [Skybox View], [Commercial], [Proprietary], [$O(N^3)$], [High],

    [NetSPA], [Restricted / not publicly available], [MPAG], [$O(N log N)$], [Moderate],

    [SeaMonster], [Open-source], [Attack Tree (AT)], [$O(N^k)$], [Moderate],

    [Cauldron], [Commercial], [EDG], [$O(N^3)$], [High],

    [FireMon], [Commercial], [MPAG], [$O(N log N)$], [High],

    [CySeMoL], [Restricted / not publicly available], [Model-based], [$O(N^k)$], [Not reported],

    [CyGraph], [Restricted / not publicly available], [Hybrid / TVA-based], [$O(N^k)$], [Very High],

    [SAGE], [Open-source], [Alert-driven], [N/A], [High],

    [AttacKG], [Open-source], [CTI-based], [N/A], [Moderate],
  ),
  caption: [Comparison of Attack Graph Generation Tools],
) <tab-attack-graph-tools>

#set text(size: 12pt)

#set par(justify: true)

Three of these tools, spanning the field's main paradigms, are examined in greater detail: MulVAL (logic-based), SeaMonster (expert-driven) and SAGE (alert-driven). Together, they illustrate the contrasting roles of formal reasoning, expert modeling and alert-driven analysis in attack graph generation.

== MulVAL

MulVAL is a well-established foundation for security modeling and attack graph analysis, with strong and sustained adoption within the research community. Since its introduction in 2005, it has been referenced and used in hundreds of publications #cite(<KM23>, form: "normal"), demonstrating both its maturity and its recognition as a standard approach for logic-based attack graph generation.

Beyond its widespread use, MulVAL has proven to be highly extensible. A substantial body of work builds directly on the framework by introducing new interaction rules or by proposing methodologies for defining such rules. Rather than developing entirely new models, researchers have consistently chosen to extend MulVAL, underscoring its flexible design and long-term viability as a research platform #cite(<KM23>, form: "normal").

=== Architecture and Data Integration

MulVAL is an open-source framework released under the @gpl, a license that grants users the right to study, modify and redistribute the software #cite(<MULVAL_PROJECT13>, form:"normal"). It is designed to help security practitioners and administrators analyze, manage and monitor the security configurations of enterprise networks #cite(<OU_GOVINDAVAJHALA_APPEL05>, form:"normal"). MulVAL leverages data from vulnerability databases and scanning tools to reason about network configurations and to generate potential attack traces, which describe how an attacker could exploit existing weaknesses to reach a specified objective. The resulting analysis can further support the selection of countermeasures, such as patching vulnerable software, modifying network topology or adjusting access permissions.

The MulVAL distribution includes an adapter for the NVD that automatically downloads vulnerability specifications and synchronizes them with a MySQL database #cite(<MULVAL_PROJECT13>, form:"normal"). This synchronization is designed to run periodically so that the local repository reflects the most recent vulnerability information. The stored data are then used by MulVAL adapters to translate the output of vulnerability scanning tools into a format suitable for analysis by the MulVAL engine.

These adapters allow MulVAL to consume current vulnerability and scan data when the corresponding synchronization and scanning processes are performed. They do not determine whether an update is relevant to a particular modeled environment before inference is executed, nor do they distinguish changes that alter the logical attack surface from those that only affect the priority of existing paths.

MulVAL currently provides two primary adapters. The first processes @oval reports, a standardized language for assessing and reporting the configuration and security state of computer systems #cite(<OVAL_GUIDE26>, form: "normal"). The second adapter consumes Nessus#footnote[https://www.tenable.com/products/nessus] scan results, where @nessus is a widely used vulnerability scanner that identifies misconfigurations, missing patches and known weaknesses in networked systems. Both adapters produce a structured description of detected vulnerabilities on scanned hosts, expressed in the input format required by the MulVAL analyzer #cite(<MULVAL_PROJECT13>, form:"normal").

=== Reasoning Mechanism

MulVAL generates attack traces by combining a rule file, which can be extended with custom interaction rules, and an input file describing the target environment #cite(<OU_GOVINDAVAJHALA_APPEL05>, form:"normal"). Both files are written in @datalog, a declarative logic language and subset of @prolog that supports efficient, rule-based reasoning. The analysis is executed using the @xsb logic programming engine, whose tabled resolution mechanism reuses intermediate results and avoids infinite recursion #cite(<KLOS18>, form:"normal"). As a result, attack traces are constructed in polynomial time #cite(<OU06>, form:"normal"). This gives MulVAL a clear and formal specification of attack reasoning while keeping performance practical for realistic inputs.

The MulVAL rule base describes common attack scenarios, including the exploitation of software vulnerabilities and privilege escalation patterns. To perform an analysis, MulVAL requires several categories of input #cite(<OU_GOVINDAVAJHALA_APPEL05>, form:"normal"):
- Vulnerability declarations, including classifications, consequences and the presence of vulnerabilities on specific hosts, typically obtained through MulVAL adapters;
- Host configuration information, such as installed software, user and process privileges, and active network services with their associated protocols and ports;
- Network configuration details, specifying connectivity between hosts, ports and protocols;
- Principals and access control information, describing users, files and permission relationships;
- Component interaction definitions, modeling how system elements interact;
- Attacker specifications, including initial access, network location and attack goals.

MulVAL input files consist of a human-readable set of primitive predicates that express system configurations and preconditions. Derived predicates, defined by interaction rules, represent the post conditions or outcomes of exploits, from which the final attack graph is generated #cite(<OU_GOVINDAVAJHALA_APPEL05>, form:"normal").

@lst-mulval-specification presents a simplified example. A host named _webServer_ runs an HTTP service accessible from the internet, while a second host, _fileServer_, runs a Samba service that is only reachable from _webServer_. Both services contain remotely exploitable vulnerabilities:

#figure({
  ```erlang
  1. attackerLocated(internet).
  2. attackGoal(execCode(fileServer, _)).

  3. hacl(internet, webServer, tcp, 80).
  4. hacl(webServer, fileServer, tcp, _).

  5. vulExists(webServer, 'CVE1', httpd).
  6. vulProperty('CVE1', remoteExploit, privEscalation).
  7. vulExists(fileServer, 'CVE2', _).
  8. vulProperty('CVE2', remoteExploit, privEscalation).

  9. networkServiceInfo(webServer, httpd, tcp, 80, u1).
  10. networkServiceInfo(fileServer, samba, tcp, 445, u2).
  ```
},
  caption: [Simplified MulVAL attack graph specification for a multi-hop attack scenario #cite(<KLOS18>, form:"normal")]  
) <lst-mulval-specification>

Line 1 uses `attackerLocated` to define the attacker's initial position as the internet. Line 2 uses `attackGoal` to specify the desired outcome, namely code execution on _fileServer_. The `hacl` predicates in lines 3 and 4 describe the permitted network communication. The first grants access from the internet to the HTTP service on _webServer_ through TCP port 80, while the second allows _webServer_ to contact _fileServer_ through any TCP port. Lines 5 and 7 use `vulExists` to associate CVE1 and CVE2 with the affected hosts and, for CVE1, with the HTTP service. Lines 6 and 8 use `vulProperty` to classify both vulnerabilities as remotely exploitable and capable of privilege escalation. Finally, `networkServiceInfo` in lines 9 and 10 identifies the service, transport protocol, listening port and executing user for each host. Together, these facts allow MulVAL to infer that an attacker can compromise _webServer_ from the internet and subsequently reach _fileServer_. The graph generator can subsequently convert the resulting attack trace into several output formats, including plain text, CSV files containing graph vertices and edges, DOT files or visual representations exported as EPS or PDF #cite(<MULVAL_PROJECT13>, form:"normal").

@fig-mulval-example illustrates the attack graph produced for this scenario, where nodes correspond to derived security conditions and exploit steps, and edges represent the logical dependencies inferred by MulVAL. The highlighted path from the internet to webServer and subsequently to fileServer reflects the multi-hop attack sequence described above.

#figure(
  //image("images/generic-attack-graph.png",  width: 100%),
  image("images/mulvalgraphexample.png",  width: 100%),
  caption: [Example of a MulVAL-generated attack graph #cite(<KLOS18>, form: "normal")], 
) <fig-mulval-example>

=== Limitations

MulVAL ships with only a basic set of interaction rules that primarily model exploit behavior at the network level. This standard rule set recognizes just three kinds of exploitability #cite(<KLOS18>, form:"normal"): local vulnerabilities, which require the attacker to already run code on the target host, remote vulnerabilities, which require only network access, and client-side vulnerabilities, which are triggered when a vulnerable client interacts with a malicious remote party. In addition, the default rules assume that every successful exploit results in privilege escalation, so other kinds of impact cannot be represented #cite(<KLOS18>, form:"normal"). Consequently, attack paths whose primary outcomes are data disclosure, data modification or service disruption cannot be represented as distinct logical consequences, which restricts the range of security goals that the graph can express.

Further limitations restrict MulVAL's applicability to modern infrastructures. It has no native notion of virtual hosts and does not represent the physical machines on which they run, offering only limited support for virtualized or clustered environments #cite(<KLOS18>, form:"normal"). It also cannot express combinations of prerequisites that must hold together for an exploit to succeed #cite(<KLOS18>, form:"normal"). Together, these constraints limit the expressiveness of the generated attack graphs for contemporary, highly dynamic systems.


== SeaMonster

SeaMonster is a graphical security modeling tool designed to support the structured analysis of software vulnerabilities from multiple complementary perspectives. Rather than introducing new modeling formalisms, SeaMonster integrates established techniques within a unified information model, enabling analysts to relate the causes of vulnerabilities, potential attack paths and corresponding mitigation strategies #cite(<MELAND08>).

The tool organizes security analysis around three interconnected viewpoints:
- Vulnerability causes, focusing on the underlying design or implementation weaknesses that give rise to vulnerabilities;
- Threats and attacks, describing how those vulnerabilities can be exploited by an adversary;
- Countermeasures, addressing how vulnerabilities and their consequences can be prevented or mitigated.

Each viewpoint may contain multiple views, allowing the same system to be examined at different levels of abstraction or from alternative analytical angles. SeaMonster is extensible through a plugin based architecture and is implemented using the Eclipse Modeling Framework and the Graphical Modeling Framework, which provide support for model definition and visual editing #cite(<MELAND08>).

=== Vulnerability Causes Viewpoint

The Vulnerability Causes viewpoint is grounded in security modeling approaches that seek to identify the root causes of vulnerabilities #cite(<MELAND08>). Its primary objective is to understand why vulnerabilities arise, enabling preventive action rather than merely addressing their observable effects. Such analyses are typically conducted by security experts after recurring or representative vulnerability instances have been identified #cite(<MELAND08>).

@rca comprises a family of techniques aimed at tracing observed problems back to their underlying origins. In contrast to traditional troubleshooting (which focuses on correcting individual failures), RCA seeks to eliminate the systemic conditions that enable vulnerabilities to emerge #cite(<ANDERSEN_FAGERHAUG06>).

One widely adopted RCA technique is @fta, which models how combinations of events can lead to system failure. By using logical AND and OR operators, FTA supports a structured exploration of causal dependencies and enables reasoning about multiple interacting factors #cite(<KEMPER_SANDERS03>).

SeaMonster adopts @vcg:pl as a representation tailored to security analysis. A VCG is a directed acyclic graph composed of four node types: simple, compound, conjunction and exit nodes #cite(<BYERS06>). Simple nodes denote basic causes, while compound nodes encapsulate complex substructures that can be further decomposed. Conjunction nodes express dependencies in which multiple conditions must hold simultaneously, and exit nodes connect the model to other viewpoints #cite(<BYERS06>).

VCGs support both generalization and specialization, enabling analysts to model vulnerabilities at different levels of abstraction #cite(<BYERS06>). This capability is particularly valuable because vulnerabilities often result from combinations of factors rather than isolated causes. Through the use of compound nodes, SeaMonster facilitates incremental decomposition, allowing large models to remain visually and cognitively manageable #cite(<MELAND08>).

=== Threats and Attacks Viewpoint

The Threats and Attacks viewpoint addresses how identified vulnerabilities can be exploited to compromise a system. SeaMonster represents this perspective using attack trees #cite(<MELAND08>). In practice, threat-oriented and attack-oriented analyses are tightly interrelated, as analysts typically consider both the characteristics of potential adversaries and the concrete exploitation steps in parallel. SeaMonster therefore integrates these aspects into a single viewpoint, reflecting how attack trees are constructed and reasoned about in real-world security assessments.

Attack trees are often developed early in the system lifecycle to assess the attack surface and to reason about potential risks and consequences before implementation decisions are finalized. The relevance of particular attack paths depends strongly on the assumed attacker model. SeaMonster therefore encourages explicit consideration of attacker characteristics such as skill level, available resources, access privileges, risk tolerance and motivation #cite(<MELAND08>).

=== Countermeasures Viewpoint

The Countermeasures viewpoint addresses how vulnerabilities can be prevented and how the threats and attacks they enable can be mitigated #cite(<MELAND08>). It complements the previous viewpoints by shifting the focus from analysis toward risk reduction and control selection.

One modeling approach supported by SeaMonster is the extension of @uml use case diagrams with security-related concepts, commonly known as misuse case diagrams. While standard use case diagrams effectively capture functional requirements, they provide limited support for expressing security concerns #cite(<MELAND08>). Misuse case diagrams extend this notation to explicitly represent threats, vulnerabilities and their interactions with intended system functionality #cite(<SINDRE_OPDAHL05>).

In this extension, two types of mis-actors are introduced: attackers, representing external adversaries #cite(<SINDRE_OPDAHL05>), and insiders, representing authorized users who may abuse legitimate access #cite(<ROSTAD06>). Additional relationships, namely exploit, detect and prevent, link threat and vulnerability use cases to regular use cases, making mitigation strategies explicit #cite(<MELAND08>). When applied judiciously, misuse case diagrams provide a high-level overview of security requirements and countermeasures and serve as an effective communication tool among stakeholders #cite(<MELAND08>).

SeaMonster also supports security activity graphs, which offer a more detailed and process-oriented representation of countermeasures. These graphs describe concrete activities that can mitigate a vulnerability, often derived directly from a corresponding VCG #cite(<ARDI06>). The root node represents the vulnerability, while leaf nodes denote preventive or mitigating activities. Logical gates capture dependencies and alternative mitigation strategies #cite(<ARDI06>).

Compared with misuse case diagrams, security activity graphs provide finer grained guidance for design, implementation and testing. They are particularly useful for reasoning systematically about which combinations of activities are sufficient to mitigate a vulnerability and the associated level of effort or cost #cite(<ARDI06>). As such, they complement higher-level views and are most effectively developed by security experts as part of a broader security analysis framework.

=== Limitations

Despite its integrative design, SeaMonster presents some limitations. The tool focuses primarily on qualitative modeling and does not provide native support for probabilistic reasoning or quantitative risk estimation. Furthermore, attack trees and VCGs must be manually constructed by experts, a process that can be time-consuming and subject to analyst bias #cite(<MELAND08>). The approach is largely oriented toward design-time analysis and offers limited automation for incorporating real-world vulnerability data or scan results #cite(<MELAND08>). Finally, scalability can become problematic in large environments, as graphical models may grow complex and difficult to maintain.


== SAGE 

@sage is an unsupervised visual analytics system designed to automatically derive attack graphs from intrusion detection alerts #cite(<NADEEM21>). Unlike expert-driven modeling approaches, SAGE operates directly on raw alert data and does not require prior knowledge of system architecture, vulnerability databases or manual model construction #cite(<NADEEM21>). It therefore operates after the fact, reconstructing attacks from alerts generated by a live, monitored environment, and cannot be applied to a system that is still being designed or built.

SAGE groups intrusion alerts from the same attacker and victim pair and attack stage within fixed time windows, producing @hyperalert:pl. It then derives temporally ordered episodes from these groups. Temporal and probabilistic dependencies between these episodes are learned using a @spdfa #cite(<NADEEM21>). This model captures both short and long-term relationships between alerts while maintaining a deterministic and interpretable structure #cite(<NADEEM21>).

A central design objective of the S-PDFA is to emphasize infrequent but high severity alert sequences that are more likely to correspond to meaningful attack behavior #cite(<NADEEM21>). To avoid overgeneralization, the model distinguishes between episodes that share identical signatures but occur in different contexts #cite(<NADEEM21>). When the statistical properties of the preceding or subsequent alerts differ, such episodes are represented as distinct states in the automaton, preserving contextual differences between attack paths #cite(<NADEEM21>).

From the learned S-PDFA, SAGE extracts objective-oriented attack graphs on a per victim and per objective basis #cite(<NADEEM21>). Each graph provides an aggregated view of relevant alerts, where attack paths originate from starting vertices and converge toward a designated objective vertex. Individual attack attempts are decomposed into separate paths, enabling comparative analysis across attackers and objectives #cite(<NADEEM21>). Attacker identities are encoded through edge coloring, with source IP addresses associated with corresponding starting vertices #cite(<NADEEM21>).

To reduce visual clutter, SAGE applies a post-processing step that filters low severity episodes, which tend to occur frequently and can dominate the visualization #cite(<NADEEM21>). This filtering highlights rare, high-impact behaviors and their contextual variations, improving interpretability for analysts.

SAGE is intended to complement existing @ids:pl, which monitor network or host activity to identify potentially malicious events, and SIEM platforms, which aggregate and correlate security logs from multiple sources for centralized monitoring. By learning patterns directly from IDS alerts through the S-PDFA model, SAGE provides an AI-enabled capability, where attack graphs are derived automatically using unsupervised probabilistic learning rather than manually defined rules #cite(<NADEEM21>). The extracted graphs support alert triage, forensic analysis and visual exploration, enabling analysts to reconstruct past attacks, compare alternative strategies and identify recurring behavioral patterns #cite(<NADEEM21>). The approach further supports attacker fingerprinting and ranking based on the severity and uniqueness of observed behaviors, thereby enhancing cyber threat intelligence while reducing analyst workload.

@fig-sage illustrates an alert-driven attack graph generated by SAGE for a data exfiltration scenario over the _remoteware-cl_ service. The nodes correspond to contextual states learned by the S-PDFA, while the edges represent probabilistic dependencies between temporally related alert episodes. State identifiers encode the surrounding context of each alert, enabling the model to distinguish behaviorally different attack paths even when they involve identical alert signatures #cite(<NADEEM21>, form: "normal").

#figure(
  //image("images/generic-attack-graph.png",  width: 100%),
  image("images/sage.png",  width: 80%),
  caption: [An alert-driven attack graph of data exfiltration over _remoteware-cl_ (IDs are state identifiers, capturing context) #cite(<NADEEM21>, form: "normal")], 
) <fig-sage>

=== Limitations

Although SAGE enables automated extraction of attack graphs from IDS alerts, several limitations affect its reliability and general applicability. Learning from infrequent sequences remains inherently difficult. When high severity sink states (terminal states representing attack objectives) are included in the training data, the resulting attack graph may present distinct objective types for behaviorally similar sequences. While this occurs rarely, the current approach does not provide a mechanism to reconcile such inconsistencies #cite(<ADAGGUSPDFA>).

A second limitation arises from the fact that only state sequences that reach a predefined objective are incorporated into the corresponding attack graph. In practice, adversaries may distribute their actions across multiple partial sequences, such that the complete attack path becomes visible only when these fragments are combined. The current construction process cannot natively merge such distributed behaviors #cite(<ADAGGUSPDFA>).

Third, the S-PDFA model is sensitive to small perturbations in alert sequences at test time. Although robustness could be improved by augmenting the training set with perturbed traces, this would distort the true data distribution and was therefore not adopted #cite(<ADAGGUSPDFA>). In addition, the framework lacks a reliable metric for evaluating model interpretability, since standard model comparison criteria are not applicable when each objective yields an S-PDFA with a different structure, number of states and training data, making the resulting scores incomparable and largely reflective of model size rather than explanatory quality #cite(<ADAGGUSPDFA>).

Beyond these methodological issues, SAGE also inherits practical limitations from its alert-driven nature. The approach depends heavily on the quality of IDS alerts. False positives, missing events or inconsistent signatures can directly distort the extracted graphs. Because SAGE reasons solely from observed alerts rather than system configuration or vulnerability knowledge, it may omit feasible but unobserved attack paths, and the resulting graphs represent behavioral correlation rather than verified exploit causality.


== Comparative Analysis of Attack Graph Generation Approaches

@tab-mulval-seamonster-sage compares MulVAL, SeaMonster and SAGE across the dimensions most relevant to their use in security analysis. It highlights their distinct sources of knowledge, analytical paradigms and practical constraints.

#set text(size: 10pt)

#set par(justify: false)

#figure(
  table(
    columns: (1.2fr, 1.9fr, 1.9fr, 1.9fr),
    inset: 7pt,
    align: left + horizon,
    // stroke: (x, y) => if y == 0 { (bottom: 1.5pt + black) } else { (bottom: 0.5pt + silver) },

    stroke: (x, y) => (
    // Horizontal line logic: Stronger line under the header (row 0)
    bottom: if y == 0 { 1.5pt + black } else { 0.5pt + silver },
    
    // Vertical line logic: Stronger line after the first column (col 0)
    right: if x == 0 { 1.5pt + black } else { 0pt }
  ),
    fill: (col, row) => if row == 0 or col == 0 { luma(240) },

    table.header(
      [*Dimension*], [*MulVAL*], [*SeaMonster*], [*SAGE*],
    ),
    
    [*Primary Objective*],
    [Predict feasible attack paths from system configuration and vulnerabilities.],
    [Explain vulnerability causes, attack logic and countermeasures.],
    [Reconstruct attacks from operational IDS alerts.],
    
    [*Knowledge Source*],
    [Formalized topology, vulnerabilities, privileges.],
    [Expert knowledge encoded in graphical models.],
    [Empirical alert data from IDS/SIEM.],
    
    [*Core Assumptions*],
    [Input data are accurate and sufficiently complete.],
    [Analyst abstraction correctly reflects the system.],
    [Alerts capture meaningful attacker behavior despite noise.],
    
    [*Automation Level*],
    [High: automatic graph generation after input acquisition.],
    [Low: manual model creation and maintenance.],
    [High: graphs learned automatically from sequences.],
    
    [*Analytical Paradigm*],
    [Logic reasoning (Datalog/XSB).],
    [Multi-view conceptual modeling.],
    [Probabilistic sequence learning (S-PDFA).],
    
    [*Nature of Graph*],
    [Logic-derived, exhaustive within the model.],
    [Conceptual/explanatory structures.],
    [Alert-driven empirical structures.],
    
    [*Attack Coverage*],
    [All attacks feasible under assumptions.],
    [Only modeled scenarios.],
    [Only attacks that generated alerts.],
    
    [*Lifecycle Phase*],
    [Pre-deployment configuration analysis and what-if reasoning.],
    [Design-time threat and mitigation analysis.],
    [Run-time monitoring and forensics.],
    
    [*Scalability Driver*],
    [Rule complexity and model size.],
    [Human effort and visual complexity.],
    [Alert volume and IDS quality.],
    
    [*Maturity*],
    [Long-term research adoption and tooling.],
    [Academic prototype environment.],
    [Research system validated on datasets.]

  ),

  caption: [Comparative analysis of MulVAL, SeaMonster and SAGE],
) <tab-mulval-seamonster-sage>


#set text(size: 12pt)

#set par(justify: true)


The three approaches address complementary yet fundamentally different aspects of security analysis. SeaMonster emphasizes explanatory modeling, enabling analysts to reason about the causes of vulnerabilities, potential attack strategies and corresponding countermeasures within a unified conceptual framework. Its primary strength lies in supporting expert-driven understanding and communication, particularly during early design and risk assessment. This flexibility, however, depends heavily on manual modeling effort and analyst expertise, which limits scalability and repeatability.

SAGE adopts an empirical, behavior-centric perspective, deriving attack graphs directly from IDS alerts through probabilistic learning. This enables effective forensic reconstruction, alert triage and threat intelligence without requiring prior knowledge of the system architecture. The approach is inherently constrained to attacks that generate alerts. It cannot reason about unobserved or hypothetical attack paths, nor assess the security impact of configuration changes.

MulVAL provides a predictive and formal approach, reasoning over explicit representations of configuration, vulnerabilities and attacker assumptions to enumerate all attack paths that are possible within the modeled environment. Although its expressiveness depends on the available rule set and input abstractions, MulVAL offers strong guarantees of soundness and coverage under those assumptions, making it particularly suitable for proactive analysis.

== Chapter Summary

This chapter reviewed foundational representations used to generate attack graphs, including state graphs, Exploit Dependency Graphs, Logical Attack Graphs, Bayesian Attack Graphs and Multiple Prerequisite Attack Graphs. It then compared selected tools and examined MulVAL, SeaMonster and SAGE in detail. The comparison showed that MulVAL offers the most appropriate basis for this work because it combines formal reasoning, extensibility and automated generation from environmental and vulnerability facts.

The analysis also highlighted the limitations of static model generation and the lack of systematic integration between threat intelligence and attack graph reasoning. The next chapter presents the design and implementation of a framework that addresses these limitations by combining MulVAL with threat intelligence ingestion, environment correlation, orchestration and dynamic risk analysis.

= Design and Implementation <ch-design>

== Problem Statement

Modern cybersecurity environments are characterized by continuous structural change. New vulnerabilities are disclosed on a daily basis, infrastructures evolve rapidly and adversaries constantly adapt their tactics, techniques and procedures #cite(<GM19>, form: "normal"). MulVAL performs static logical inference over the facts supplied to a given execution, so that each generated attack graph reflects the system and intelligence available at that time #cite(<GM19>, form: "normal"). This characterizes an individual inference run, rather than an inability to refresh its inputs. Existing MulVAL adapters can periodically update vulnerability repository data and translate scanner output before a later execution #cite(<MULVAL_PROJECT13>, form: "normal"). The proposed framework complements these capabilities by correlating refreshed threat intelligence with an asset inventory expressed through CPEs before invoking MulVAL. It therefore supports analysis where vulnerability scans cannot be performed or are inappropriate. It determines whether refreshed information changes the vulnerability facts for the modeled environment and therefore requires graph regeneration, or whether the information affects only the contextual risk of existing paths.

A separate gap remains between threat modeling practices and automated attack graph generation #cite(<LE23>). While threat modeling frameworks aim to identify and characterize potential adversarial behavior, their outputs are rarely integrated in a systematic manner into automated attack graph construction processes. The proposed framework addresses this gap by translating threat modeling outputs into MulVAL facts alongside correlated vulnerability facts.

As discussed in @ch-background and @ch-state-of-the-art, attack graphs provide a structured mechanism for modeling multi-stage adversarial behavior and reasoning about feasible attack paths within a networked system #cite(<LALLIE20>, form: "normal"). They show which assets an attacker can reach and through which paths, but structural reachability alone does not establish which feasible paths should be mitigated first. The framework therefore combines CVSS, EPSS, KEV status and asset criticality to calculate and rank path risk scores. It repeats this calculation during every execution, even when the graph structure is unchanged, so that revised threat intelligence or organizational context can update mitigation priorities without invoking MulVAL again. Accordingly, this dissertation examines how selective structural regeneration, threat modeling integration and contextual path risk scoring can be combined within a single workflow.

== Conceptual Solution <sec-conceptual-solution>

This section presents the conceptual design of the proposed framework. It describes the architectural decisions, design goals and overall structure through which dynamic threat intelligence and threat modeling are integrated into attack graph generation. Its concrete realization, including the technologies and algorithms employed, is described in @sec-implemented-solution.

#figure(
  image("images/conceptual_architecture.png", width: 90%),
  caption: [Conceptual architecture of the proposed framework.],
) <fig-conceptual-architecture>

@fig-conceptual-architecture shows the inputs, processing stages and outputs of the framework. The environment model and the STRIDE threat model are combined during environment correlation and threat modeling integration, while external threat intelligence is ingested into a shared knowledge base and matched to asset CPEs. The resulting enriched MulVAL facts pass through change detection and orchestration, which invokes the MulVAL reasoning engine when a structural change is detected. The logical attack graph is then combined in post-processing with current risk information from the knowledge base and with the configured asset criticality and CIA priorities, producing annotated attack graphs, risk reports and delta reports. The following sections develop the design decisions represented in this flow.

=== Selection of the Logical Reasoning Engine

The selection of the logical reasoning engine constitutes a critical architectural decision within the proposed framework. The reasoning engine determines how system configurations, vulnerabilities and adversarial capabilities are represented and how potential attack paths are derived from these inputs.

Several attack graph generation approaches were analyzed in @ch-background and @ch-state-of-the-art. Among the evaluated options, MulVAL emerges as the most suitable foundation for the proposed framework. MulVAL represents one of the most established and widely adopted academic systems for logical attack graph generation #cite(<TAY_BAU23>). Its extensive use in prior research demonstrates both its robustness and its extensibility across multiple security analysis applications.

MulVAL provides automated attack graph generation based on a formal logical reasoning model. Unlike purely topological or alert-driven approaches, MulVAL relies on a Datalog-based inference engine, enabling explicit modeling of exploit preconditions, vulnerability relationships, privilege escalation mechanisms, and dependency chains between attack steps. Through declarative inference rules, attack paths can be derived logically rather than through hard-coded procedural logic #cite(<OU_GOVINDAVAJHALA_APPEL05>, form:"normal"). This approach significantly improves modularity and extensibility.

Another important advantage of MulVAL lies in its ability to integrate heterogeneous system information. The framework supports inputs describing host configurations, network connectivity and vulnerability information such as CVE-based data #cite(<OU_GOVINDAVAJHALA_APPEL05>, form:"normal"). This flexible fact-based representation makes MulVAL particularly suitable for integration with external data sources, including CTI and OSINT pipelines, which form a central component of the dynamic framework proposed in this dissertation.

MulVAL also cleanly separates the facts describing an environment from the interaction rules that reason over them. The model can therefore be updated simply by changing its facts, without touching the reasoning logic, which provides a natural foundation for incremental updates and dynamic re-evaluation as the environment evolves.

Due to its strong academic foundation, open-source availability, and demonstrated extensibility, MulVAL has been widely adopted as a research platform for attack graph generation and security analysis. Its extensive use in prior work further highlights its suitability as a foundational reasoning engine for advanced security modeling frameworks #cite(<TAY_BAU23>, form: "normal"). Consequently, MulVAL is selected in this work not merely as an attack graph generation tool, but as the core logical inference engine underpinning the proposed dynamic attack modeling framework.

=== Selection of the Threat Modeling Framework

Threat modeling frameworks provide systematic methodologies to identify, analyze and mitigate potential threats within a system by examining its architecture, assets and trust boundaries #cite(<OWASP1>, form: "normal"). Integrating such methodologies into automated security analysis enables the incorporation of adversarial perspectives during early stages of system analysis and allows threat intelligence to be contextualized within the system’s architecture.

As discussed in the problem statement, a significant gap exists between traditional threat modeling practices and automated attack graph generation. While threat modeling frameworks identify potential adversarial actions and system weaknesses, their outputs are typically produced as qualitative analyses or documentation artifacts that are rarely integrated into automated reasoning systems #cite(<LE23>). Consequently, attack graph generation often relies primarily on vulnerability data and system configuration information, without incorporating structured representations of adversarial intent or threat scenarios.

In addition to the logical reasoning engine, the framework requires a structured methodology capable of translating threat modeling outputs into machine-processable representations. Of the frameworks analyzed in @ch-background, PASTA and OCTAVE are too heavyweight and documentation intensive for an automated pipeline, while VAST's proprietary nature limits its use in open, research-oriented settings #cite(<HAMMAMI24>, form: "normal"). STRIDE is therefore the natural candidate.

STRIDE decomposes a system into components and data flows and evaluates each against a fixed set of threat categories, so that individual threats can be tied to specific components and trust boundaries and then translated into structured, machine-processable facts #cite(<MS_STRIDE06>, form: "normal"). This structured output makes STRIDE suitable for the automated pipeline developed in this work.

Another important advantage is its compatibility with logical reasoning systems. Because STRIDE threats correspond to clearly defined adversarial actions, they can be translated into logical predicates that enrich the fact base used by the MulVAL inference engine. For instance, threats such as identity spoofing or privilege escalation can be mapped to assumptions about attacker capabilities, authentication weaknesses or trust violations. This mapping enables attack graph generation to incorporate adversarial assumptions derived from threat modeling, helping bridge the gap between qualitative threat analysis and automated attack path generation.

Although STRIDE is often criticized for its software-centric focus and limited business context, its simplicity, structured taxonomy and wide adoption make it the most practical choice for this technical, automated setting. STRIDE is therefore selected as the threat modeling methodology integrated into the proposed architecture #cite(<BN_STRIDE26>, form: "normal").

=== Design Goals

The design of the framework is guided by four goals: automated threat intelligence acquisition, a modular architecture, dynamic model evolution and efficiency during repeated analysis. Together, these goals define the functional and operational requirements of the proposed solution.

First, the framework emphasizes automation in the acquisition and integration of threat intelligence. It must support the automated ingestion, normalization and processing of multiple intelligence sources, including vulnerability disclosures with their associated CVSS severity metrics, exploit prediction scores (EPSS) and known exploited vulnerability catalogues (KEV), while remaining extensible to additional structured intelligence formats such as STIX. By automating these processes, the framework reduces the latency between intelligence publication and model adaptation, ensuring that attack graphs remain analytically relevant in rapidly evolving security environments.

Second, the architecture is designed to be modular in order to accommodate the heterogeneity of intelligence sources and analytical components. Intelligence ingestion, normalization, scoring and reasoning modules are intentionally decoupled, allowing individual components to evolve independently. This modular structure enables the integration of alternative scoring mechanisms, the replacement or extension of attack graph engines and the incremental enhancement of reasoning capabilities. Such flexibility aligns with the rule-based architecture used by MulVAL #cite(<OU06>, form: "normal").

A third design goal concerns dynamic model evolution and efficiency during repeated analysis. The framework must correlate newly disclosed vulnerabilities with asset CPEs and regenerate the graph only when the resulting facts alter the attack surface. Updates to EPSS scores, KEV status or asset criticality should instead update the prioritization of existing paths. It should also enable temporal comparisons between successive model states. By avoiding MulVAL execution when the structural fact set remains unchanged, the framework limits unnecessary recomputation. This is relevant because attack graph generation can become costly as system and vulnerability models grow #cite(<LALLIE20>, form: "normal"). The performance benefit requires dedicated measurement in larger environments and is outside the scope of this work.

=== Conceptual Architecture of the Framework

As shown in @fig-conceptual-architecture, the proposed framework adopts a layered, modular architecture built around MulVAL. It separates structural attack reasoning from intelligence acquisition, correlation and contextual risk computation, allowing each layer to evolve independently while retaining MulVAL's established reasoning model.

MulVAL derives the possible attack paths by applying a fixed set of interaction rules to a collection of facts that describe the environment and its vulnerabilities. The framework leaves these rules unchanged and lets only the facts evolve over time. This preserves compatibility with existing MulVAL rule sets and MulVAL's polynomial time performance, while all dynamic behavior comes from the surrounding layers that generate and update the facts MulVAL consumes.

Conceptually, the framework is organized into a sequence of cooperating layers, each responsible for a well-defined stage of the analytical process:

1. Threat intelligence ingestion: acquires and normalizes external intelligence into a database.
2. Environment correlation and threat modeling integration: binds relevant vulnerabilities and STRIDE-derived threats to the modeled assets, translating both into logical facts.
3. Change detection and orchestration: governs when the attack graph must be recomputed.
4. MulVAL reasoning engine: generates the LAG.
5. Post-processing and risk analysis: enriches, scores and visualizes the resulting model.

The overall system operates according to an event-driven update model, in which changes in the threat landscape or in the modeled environment trigger the selective recomputation of the attack graph. Such events may include newly disclosed vulnerabilities, significant updates to EPSS scores, modifications to the asset inventory or the appearance of vulnerabilities in the KEV catalogue. When an event affects the logical structure of the model, for example by introducing a new vulnerability on a reachable host, the attack graph is regenerated. When it affects only the contextual weighting of existing elements, such as a revised EPSS score, the model is re-scored without structural regeneration. This separation preserves the logical model while avoiding a new MulVAL execution for contextual updates.

The conceptual roles of the layers are described in @sec-conceptual-ingestion through @sec-conceptual-postprocessing. The implementation of these layers is described in @sec-implemented-solution, including the services, data flows and algorithms that realize the framework.

=== Threat Intelligence Ingestion Layer <sec-conceptual-ingestion>

The first architectural component is responsible for the automated acquisition and normalization of external threat intelligence. This layer retrieves vulnerability disclosures and their CVSS severity metrics, EPSS exploitation probabilities and KEV catalogue updates from authoritative sources. Retrieved data is parsed, normalized and deduplicated before being stored in a centralized Threat Intelligence Database. The layer is designed to be extensible, so that additional structured intelligence formats, such as STIX, can be incorporated without affecting the downstream reasoning stages.

This database functions as a persistent knowledge repository that enables temporal comparison of intelligence states and supports incremental updates. By decoupling intelligence acquisition from attack reasoning, the framework allows intelligence connectors to evolve independently without affecting the logical inference mechanisms.

=== Environment Correlation and Threat Modeling Integration Layer <sec-conceptual-correlation>

This layer links external intelligence with the local environment and, in the same step, incorporates information from threat modeling. Vulnerabilities are matched to the infrastructure through a mapping pipeline in which CVE identifiers are associated with CPE entries and then matched against the software and services installed on each asset. In parallel, STRIDE-based threat models are translated into logical facts compatible with MulVAL, so that adversarial assumptions identified during threat modeling participate in attack graph generation alongside concrete vulnerabilities.

The result is a set of vulnerability and threat facts bound to specific hosts and services. This stage therefore determines whether newly acquired intelligence introduces structural changes to the attack surface represented in the attack graph.

=== Change Detection and Model Orchestration <sec-conceptual-orchestration>

The orchestration layer governs the dynamic evolution of the model. It monitors both environmental changes and intelligence updates to determine whether logical recomputation of the attack graph is required. Structural changes such as new vulnerabilities affecting assets, topology modifications, service exposure changes, or the addition and removal of assets alter the MulVAL input facts and trigger execution of the reasoning engine.

When no structural changes are detected, logical recomputation is skipped. This conditional execution preserves the logical model while avoiding graph regeneration when only contextual information has changed.

=== Attack Graph Generation <sec-conceptual-generation>

When structural updates are detected, MulVAL is executed to regenerate the LAG. The resulting model captures feasible attack paths, privilege escalation chains, and the logical dependencies between exploit steps. Because the underlying reasoning engine remains unchanged, the framework maintains compatibility with established MulVAL rule sets while benefiting from automated updates to environmental facts.

=== Post-Processing and Dynamic Risk Analysis <sec-conceptual-postprocessing>

While MulVAL focuses on structural reachability, the final architectural layer introduces dynamic risk contextualization. After the attack graph is generated, vulnerability nodes are enriched with EPSS exploitation probability and KEV exploitation status. The risk calculation also uses asset criticality levels and CIA priorities specified by the analyst or organization in the configuration supplied to the framework before graph generation.

These attributes enable the computation of higher-level analytical metrics, including path level risk scores, identification of the highest risk attack paths, and comparative analysis between successive model states. To support temporal comparison, the post-processing component compares the risk report generated in the current execution with the report from the preceding execution. It identifies added or removed CVEs, changes in the highest-ranked paths, variation in their average risk score and newly observed KEV entries. The corresponding graph version identifiers are recorded to distinguish structural changes from risk re-prioritization.

Importantly, this post-processing stage is executed even when the logical structure of the graph remains unchanged. As a result, threat intelligence updates, such as changes in EPSS scores, can dynamically influence risk prioritization without requiring full regeneration of the attack graph.

#pagebreak(weak: true)
== Implemented Framework <sec-implemented-solution>

Whereas @sec-conceptual-solution defined the framework at a conceptual level, this section describes its concrete realization. The implemented solution materializes the layered, event-driven architecture as a set of independent, containerized services orchestrated through a single reproducible workflow. Each conceptual layer corresponds to a dedicated service that communicates either through a shared PostgreSQL#footnote[https://www.postgresql.org/] knowledge base or through file artifacts written to a common test case directory mounted into the containers. This subsection details the deployment model, the individual services, the data structures they exchange and the algorithms that implement dynamic risk analysis.

The framework and its services were designed and implemented as part of this work. These artifacts include the threat intelligence ingestion, environment correlation, STRIDE-to-MulVAL translation, change detection and orchestration, risk scoring, delta analysis and graph visualization components. MulVAL is reused as an external logical attack graph generation engine, and its interaction rules remain unmodified. Docker#footnote[https://www.docker.com/] and XSB#footnote[https://xsb.com/xsb-prolog/] are third-party technologies used to deploy or support the framework, while VulnCheck#footnote[https://docs.vulncheck.com/], FIRST EPSS and the CISA KEV catalogue are external data sources.

=== System Overview and Deployment

The framework is implemented as a modular pipeline composed of five processing services and a central database, deployed and coordinated with Docker Compose. Each stage of the conceptual architecture is encapsulated in its own container with explicitly declared dependencies, ensuring that services execute in the correct order and that intermediate artifacts are produced before they are consumed. The complete pipeline, from input artifacts to the final risk report, is illustrated in @fig-pipeline.

#figure(
  image("images/pipeline.png", width: 90%),
  caption: [End-to-end architecture of the proposed pipeline, from environment and threat intelligence inputs to the annotated attack graph and risk report.],
) <fig-pipeline>

The execution order is enforced through service dependencies. Environment correlation waits for the threat intelligence database to be available, the orchestrator waits for correlation to complete and post-processing waits for the orchestrator. Two entry points expose the pipeline to the user through a `Makefile`: `make run` executes the full workflow reusing the existing contents of the threat intelligence database, whereas `make ingest` additionally activates the optional ingestion service to refresh the database before analysis. The target environment is selected through a `SCENARIO` variable, which mounts the corresponding test-case directory into the relevant containers. This design directly supports the modularity and reproducibility goals defined in the conceptual solution, as each service can be developed or replaced independently while sharing well-defined interfaces.

The services exchange information through two complementary channels. Persistent threat intelligence (CVE, CVSS, EPSS and KEV data) is stored in a shared PostgreSQL database, while environment-specific artifacts, the Prolog scenario, the generated attack graph and the risk reports are exchanged as files within the mounted test-case directory. This dual channel design keeps the two kinds of state apart: the threat intelligence, which evolves slowly and is common to any organization, is managed separately from the environment-specific model, which changes far more frequently as new scenarios are analyzed.

=== Threat Intelligence Database

At the centre of the framework lies a PostgreSQL database that acts as the persistent knowledge base shared by the ingestion, correlation and post-processing layers. Its schema is intentionally compact and is organized around the vulnerability identifier (CVE) as the principal key, so that severity, exploitability and exploitation-status signals can be retrieved efficiently during correlation and enrichment. The logical model is depicted in @fig-threat-intel-model.

#figure(
  image("images/threat_intel_logical_model.png", width: 100%),
  caption: [Logical model of the Threat Intelligence Database, organized around the CVE identifier.],
) <fig-threat-intel-model>

The schema comprises four tables. The `cves` table stores each vulnerability together with its publication and modification timestamps and its CVSS v3.1 base score and vector. The `cve_cpe_mapping` table associates each CVE with the products it affects, expressed as CPE identifiers, thereby connecting each vulnerability to the specific software in which it occurs. The `epss` table holds the EPSS exploitation probability and percentile for each CVE, while the `kev` table records whether a vulnerability appears in CISA's Known Exploited Vulnerabilities catalogue, including the affected product, the date of addition and a flag indicating known ransomware usage. Although the `epss` and `kev` data stand in a one-to-one relationship with `cves` and could be folded into it as additional columns, they are kept as dedicated tables so that each intelligence source maps to its own table, mirroring the modular ingestion design. This separation also leaves room to store richer per-source information that is not yet exploited by the scoring model but could be in the future, such as the EPSS percentile. The schema is provisioned automatically when the database container is initialized, ensuring a consistent structure across deployments. Its complete definition is reproduced in @app-schema.

=== Threat Intelligence Ingestion

The ingestion service populates the Threat Intelligence Database from authoritative external sources. It aggregates three complementary categories of intelligence, as shown in @fig-ingestion.

#figure(
  image("images/threat_intelligence_ingestion.png", width: 78%),
  caption: [Threat intelligence ingestion: CVE/CPE and KEV data from the VulnCheck API and EPSS scores from FIRST.org.],
) <fig-ingestion>

NVD CVE records, including CVSS metrics and CPE configurations, together with the CISA KEV catalogue, are obtained through the VulnCheck API, whereas EPSS scores are retrieved as a compressed dataset from FIRST.org. The service is structured around a controller that orchestrates the sequential synchronization of the three sources, a set of source-specific handlers that fetch and transform each dataset, and a repository component that performs context-managed, batched writes into PostgreSQL. The handler preferentially extracts the CVSS v3.1 base score and vector, falling back to v3.0 when the former is absent. This choice reflects the predominance of CVSS v3.x in operational vulnerability records at the time of implementation #cite(<FIRST_CVSS30>, form: "normal"). Supporting CVSS 4.0 requires extensions to the ingestion and scoring logic to accommodate its revised metric model, and is therefore identified as future work. Synchronization proceeds in three stages: CVE records and their CPE mappings are ingested first, followed by EPSS scores and finally the KEV catalogue. Records are written using batched upsert operations, which insert new entries and update existing ones in place, while new CVE-CPE mappings are added only when they do not already exist, so that repeated runs never create duplicates. This keeps the knowledge base consistent across repeated synchronization runs while accommodating the large volume of vulnerability data efficiently. By decoupling intelligence acquisition from the reasoning stages, the ingestion connectors can evolve, or new sources can be added, without impacting the rest of the pipeline.

=== Environment Correlation

The environment correlation service is the component that binds external intelligence to the specific infrastructure under analysis, transforming a generic network description into an enriched, MulVAL-ready scenario. Its inputs and outputs are summarized in @fig-environment-correlation.

#figure(
  image("images/enviroment_correlation.png", width: 80%),
  caption: [Environment correlation: asset CPEs are matched against the database to inject vulnerability facts, optionally enriched with STRIDE derived threats.],
) <fig-environment-correlation>

Before any correlation work begins, the service applies a pre-flight quality gate to the Threat Intelligence Database. It queries the row count of each intelligence table and compares it against a configurable minimum. If any table is empty or only partially populated, for instance because an ingestion run failed midway, the pipeline is aborted immediately rather than producing an attack graph from incomplete intelligence. The minimum thresholds are conservative floors set below the expected data volumes and can be overridden in the service configuration.

The service consumes a base scenario file (`scenario*.P`) describing the network topology, connectivity and attack goals, together with an `asset_cpe_mapping.json` file that associates each asset with the CPE identifiers of its modeled services and client applications. An asset can therefore declare multiple CPEs, with each mapping identifying the vendor, product and version of a specific component. These entries are configuration inputs supplied by the analyst as part of each scenario definition. In the simulated scenarios discussed in @ch-evaluation, they were selected from the software stack defined for each asset and recorded explicitly in the corresponding `asset_cpe_mapping.json` file. The framework does not infer CPEs from the network model. In an operational deployment, the same mapping could instead be obtained from an asset inventory, software discovery tool or vulnerability scanner. When a current asset inventory is available, the CPE-based approach avoids direct interaction with the target systems and the execution of vulnerability scans during correlation. It is therefore suitable for environments in which such interaction is undesirable or not permitted, although the quality of the resulting facts depends on the accuracy of the inventory.

For every CPE, the service queries the database for the corresponding CVEs and generates the appropriate MulVAL facts, namely `vulExists()` statements binding a vulnerability to a host and service, and `vulProperty()` statements describing how the vulnerability can be exploited and its consequence. The choice of exploitation primitive depends on the type of component affected: network-facing services use `remoteExploit`, whereas client-side software such as browsers or document readers uses `remoteClient`. In both cases, the consequence is modeled as privilege escalation because the framework preserves MulVAL's standard interaction rules. Vulnerabilities whose primary effect is data disclosure, data modification or service disruption are therefore not represented as distinct logical consequences in the attack graph. Their confidentiality, integrity and availability impacts still contribute to post-processing risk scores.

These statements are injected into the scenario immediately after the configuration comment of the relevant asset, producing an enriched `scenario.P`. @lst-enriched-scenario shows an illustrative fragment of the generated output, and the complete set of input artifacts for one scenario is provided in @app-artifacts.

#figure(
```prolog
/* configuration information of webServer */
vulExists(webServer,'CVE-2021-41773',httpd).
vulProperty('CVE-2021-41773',remoteExploit,privEscalation).
networkServiceInfo(webServer, httpd, tcp, 80, apache).
```,
  caption: [Illustrative fragment of the enriched `scenario.P` produced by the environment correlation layer.],
) <lst-enriched-scenario>

Optionally, the service integrates a STRIDE threat model supplied as `stride_definition.json`. A dedicated handler performs two reference checks. First, every threat must target an asset declared in the STRIDE model's own asset list. Second, every asset declared in the STRIDE model must also exist in the system configuration given by the asset mapping. It further verifies that each threat belongs to a valid STRIDE category. Validated threats are then translated into additional vulnerability facts: each STRIDE category is mapped to a MulVAL exploitation primitive and each declared impact to a consequence. The rationale and complete mapping tables are given in @app-stride. This allows adversarial assumptions derived from threat modeling to participate in attack graph generation alongside concrete CVEs, realizing in practice the conceptual bridge between qualitative threat modeling and automated reasoning. To support temporal comparison and reproducibility, each previously generated scenario is archived, with a UTC timestamp, into a rotating registry that retains the most recent versions.

=== Orchestration

The orchestration service governs when the MulVAL reasoning engine is invoked, implementing the conceptual distinction between structural and contextual updates. Its decision logic is summarized in @fig-orchestration.

#figure(
  image("images/orchestrator_v2.png", width: 100%),
  caption: [Orchestrator change detection: MulVAL is executed when a prior graph or archived scenario is absent, or when normalized scenario facts change.],
) <fig-orchestration>

When invoked, the orchestrator first checks whether attack graph outputs already exist. If none are present, MulVAL is executed unconditionally. If a graph exists but no archived scenario is available, the graph is also regenerated. Otherwise, the service compares the current enriched scenario against the previously processed one using a two-phase strategy: a SHA-256 hash of both files acts as an inexpensive equality test, and only when the hashes differ does the comparator extract and compare the scenario facts. The comparison ignores comments and whitespace, then identifies additions, removals and modifications to facts. It consequently detects changes to `vulExists` and `attackGoal`, as well as changes to topology and service configuration facts such as `hacl` and `networkServiceInfo`. Adding or removing an asset also changes its associated facts and is detected through the same mechanism. If the fact sets are unchanged, regeneration is skipped and the existing graph is reused. If any difference is detected, or if execution is explicitly forced, MulVAL is re-executed. This change detection strategy, implemented by a scenario comparator and a MulVAL executor component, prevents redundant graph regeneration during repeated analyses of an unchanged scenario.

==== Attack Graph Generation

When regeneration is required, the orchestrator invokes MulVAL on the enriched scenario. MulVAL applies its static interaction rules to the environmental and vulnerability facts and derives the LAG, capturing feasible attack paths, privilege escalation chains and the logical dependencies between exploit steps. The engine emits the graph both as a Graphviz#footnote[https://graphviz.org/] description (`AttackGraph.dot`) and as a pair of comma-separated files, `VERTICES.CSV` and `ARCS.CSV`, which enumerate the graph nodes and edges respectively. Nodes are typed as disjunctive (`OR`) capability nodes, conjunctive (`AND`) rule application nodes, or `LEAF` nodes representing base facts such as vulnerabilities and network configuration. Because the rule base is left unmodified, the framework remains fully compatible with established MulVAL rule sets while benefiting from the automatically updated fact base produced by the preceding layers.

=== Post-Processing and Dynamic Risk Scoring

The post-processing service transforms the structural attack graph produced by MulVAL into actionable risk intelligence. It implements the contextual dimension of the framework, enriching and scoring the graph using threat intelligence even when its logical structure is unchanged. The service operates as a multi-stage pipeline: it parses the MulVAL output into an in-memory AND/OR graph, enriches vulnerability nodes with data from the database, computes path-level risk scores, performs delta analysis against the previous report and finally renders annotated visualizations. Its top-level inputs and outputs are shown in @fig-post-processing.

#figure(
  image("images/post_processing.png", width: 86%),
  caption: [Top-level view of the post-processing service: its file and database inputs and the risk report and annotated graphs it produces.],
) <fig-post-processing>

The risk scoring model proposed in this work provides a transparent and reproducible comparative prioritization of attack paths. Its formulation, including its functional form and numerical parameters, was defined in this work as a comparative heuristic rather than fitted, calibrated or optimized against empirical data. The case studies demonstrate deterministic behavior and relative prioritization rather than validate the numerical scores as estimates of compromise likelihood or impact in real environments. The model combines signals with distinct roles. EPSS captures estimated exploitation likelihood. CVSS captures technical severity. KEV identifies confirmed exploitation. The CIA priorities and asset criticality represent the organization's assessment of impact. The numerical multipliers are design parameters selected to retain a bounded 0 to 10 scale and to make the contribution of each signal explicit. They can be adjusted to reflect the risk appetite and operational priorities of a given organization.

Facts derived from STRIDE influence the graph structure but do not directly contribute to the numerical risk score in the current implementation. Since these facts do not identify a CVE, they are not enriched with CVSS, EPSS or KEV data. A derivation from a goal node to a leaf node that ends in a STRIDE fact therefore receives a vulnerability based score of zero and is visually distinguished in the annotated graph. This avoids assigning unsupported numerical values to qualitative threats, but it does not quantify their relative priority.

Risk is computed in two stages. First, each vulnerability leaf node receives a base risk score on a 0 to 10 scale that combines its exploitation probability, severity, impact profile and exploitation status:

$ "base_risk"(v) = "min"(10, "EPSS"(v) times "CVSS"(v)/10 times k_("CIA")(v) times k_("KEV")(v) times 10) $

where $"EPSS"(v)$ is the exploitation probability, $"CVSS"(v)$ is the CVSS v3.1 base score (falling back to the v3.0 base score when no v3.1 score is available), and the two multipliers capture asset specific impact prioritization and active exploitation respectively. The @cia multiplier weights the confidentiality, integrity and availability impacts of the vulnerability according to per asset priority levels. These priority levels are contextual inputs defined by the organization and assigned by the analyst for each asset in the `asset_cpe_mapping.json` file. The configured priority of each CIA dimension is selected from `LOW`, `MEDIUM` and `HIGH`, which correspond to weights of $0.25$, $0.5$ and $1.0$. They express the relative importance that the organization attributes to confidentiality, integrity and availability for that asset. If an asset has no explicit configuration, the post-processing service applies global default priorities, which assign `MEDIUM` to all three dimensions:

$ k_("CIA")(v) = 0.5 + (C(v) dot w_C + I(v) dot w_I + A(v) dot w_A) / (w_C + w_I + w_A) $

in which $C(v)$, $I(v)$ and $A(v)$ denote the confidentiality, integrity and availability impacts read from the CVSS vector. The CVSS impact values are distinct from the configured priorities. Each takes the value $0$ for no impact, $0.5$ for low impact and $1.0$ for high impact. CVSS v3 defines no medium impact value. The weighting is interpreted relatively: when all three dimensions share the same priority level the multiplier collapses to a neutral value of $1.0$, so that prioritization only takes effect when an analyst deliberately favors one dimension over the others.

The KEV multiplier is applied independently of the CIA multiplier and amplifies vulnerabilities with confirmed exploitation:

$ k_("KEV")(v) = cases(1.5 "if" v in "CISA KEV", 1.0 "otherwise") $

In the second stage, the scorer enumerates the root-to-leaf attack paths and assigns each path $P$ a _path risk score_ derived from its highest risk vulnerability $v^*$, adjusted by asset criticality and path directness:

$ "path_risk"(P) = "min"(10, "base_risk"(v^*) times alpha times (1 + d(P))) $

where $alpha$ is a configurable asset criticality factor selected from four named levels: `LOW` ($0.4$), `MEDIUM` ($0.7$), `HIGH` ($1.0$) and `CRITICAL` ($1.3$). They retain $1.0$ as the neutral reference, reduce the contribution of assets below the `HIGH` level and amplify the contribution of `CRITICAL` assets, while the outer minimum keeps the final path risk score within the 0 to 10 scale. The term $d(P) = 1 / log_2(|P| + 2)$ is a directness factor. Because its value decreases as the path grows longer, it gives greater weight to shorter paths, which represent more direct routes to the goal. The full set of scoring parameters is listed in @app-scoring.

Two boundary cases are handled explicitly. When the vulnerabilities on a path carry no CVSS data at all, the path risk cannot be computed and is left undefined. Such paths are deliberately ranked at the very top of the report so that an analyst can review them manually. Conversely, a path whose derivation includes no CVE based vulnerability has no evidence based score to quantify and is assigned a score of zero, ranking it last. To enumerate the root-to-leaf paths, the graph is traversed depth first from each goal and bounded by a configurable maximum depth that also guards against cycles. The resulting paths are then deduplicated through content hashing and ranked by descending risk, with the highest-ranked paths retained in the summary report. This scoring model implements the dynamic reprioritization goal of the framework, since a change in any input signal, such as a rising EPSS score or a newly catalogued KEV entry, immediately propagates to the path rankings without requiring structural regeneration of the graph.

==== Delta Analysis and Decision Support

A distinctive feature of the proposed solution is its ability to reason about how risk evolves over time. Before each run, the previous risk report is archived, and after scoring, a delta analyzer compares the current and previous reports to surface meaningful changes. The resulting delta report identifies newly introduced and removed CVEs, changes in the ranking of the most critical attack paths, the variation in average top path risk and any newly catalogued KEV entries. This comparison between successive model states ($t_0$ versus $t_1$) provides analysts with direct visibility into emerging threats and shifting exposures, realizing the temporal comparison capability envisioned in the conceptual design.

To translate these analytical results into intuitive insight, this work extends the post-processing service with a component that renders color coded visualizations of the attack graph. The detailed annotated graph overlays the computed risk levels onto the MulVAL output, highlighting the most critical attack paths and the vulnerabilities that drive them. This detailed view is always produced, both as Graphviz sources and as rendered PDF and PNG images, while the complete analysis is persisted as a structured JSON report. An example of a detailed annotated attack graph generated by the post-processing service is shown in @fig-annotated-graph-example.

#figure(
  image("images/annotated_graph_example.png", width: 100%),
  caption: [Illustrative detailed attack graph.],
) <fig-annotated-graph-example>

==== Host-Level Summary Graph

The attack graph produced by MulVAL is complete but hard to read: in complex environments it easily contains hundreds or thousands of nodes that mix individual exploit steps, rule applications and base facts. This detail is necessary for the formal reasoning, but it offers little help to an analyst who must quickly decide where to act. To address this visualization limitation, this work further extends the post-processing service with an optional condensed _host-level summary graph_. It reduces the detailed model to a simple host-to-host map built from the highest-ranked attack paths. This representation improves visual legibility but does not reduce the cost of MulVAL inference or path enumeration.

In this graph, each node is a host rather than a single fact, and carries the information an analyst actually needs: the highest privilege the attacker gains on that host (for example, user or root), its worst case path risk, whether any of its vulnerabilities are listed in the CISA KEV catalogue, and the CVEs used to reach it. Host nodes use the same risk colors as the detailed graph, and separate colors mark where the attacker starts and the target host. Arrows show the attacker moving from one host to the next and are labelled with how many of the top paths pass through each step, so the hosts that most attack paths go through, are easy to spot. A configurable limit on how many paths are included lets the analyst balance completeness against readability. A representative host-level summary generated from a multi-tier illustrative topology is shown in @fig-host-level-summary-example.

#figure(
  image("images/host_level_summary_example.png", width: 100%),
  caption: [Illustrative host-level summary graph generated by the post-processing service.],
) <fig-host-level-summary-example>

The graph's value lies in the detail it omits. The detailed graph records every exploit and dependency, but becomes difficult to interpret as the environment grows. The summary presents attacker progression at the host level, retaining reachability, sequence, attained privilege and the concentration of selected paths. Together with the detailed annotated graph and JSON report, it provides a compact view of current attack exposure and path risk.

== Chapter Summary

This chapter described the proposed framework as a modular pipeline built around MulVAL. It covered the logical reasoning engine and STRIDE integration, intelligence flow from ingestion to environment correlation, structural update orchestration and post-processing for path scoring, comparison and visualization. The implementation separates stable MulVAL interaction rules from the evolving fact base, allowing updated intelligence to change risk prioritization without unnecessary graph regeneration.

The system transforms infrastructure descriptions and current threat intelligence into enriched attack graph outputs. The next chapter evaluates it through increasingly complex case studies.

= Case Study and Evaluation <ch-evaluation>

This chapter evaluates the framework presented in @ch-design through a set of case studies of increasing complexity and realism. The evaluation has two complementary goals. First, it demonstrates that the pipeline operates as a complete workflow across representative network environments, transforming a plain network description into an enriched and prioritized attack graph informed by threat intelligence and by facts derived from STRIDE threat modeling. Second, it assesses the dynamic behavior that distinguishes the proposed approach from a conventional, static attack graph generator. The evaluation therefore combines a qualitative analysis of each scenario with a quantitative comparison of structural metrics and dynamic re-prioritization.

The chapter is organized as follows: The experimental setup describes the methodology, the deployment environment and the configuration common to all experiments. Three simulated case studies are then presented in order of increasing complexity: a client-side exposure scenario, a multi-tier e-commerce deployment and an enterprise healthcare information system. The chapter closes with a comparative discussion that relates the observed results to the objectives defined in Chapter 1.

== Experimental Setup

The framework was evaluated using three simulated test scenarios, each describing a distinct network environment together with its asset inventory, software stack, network reachability and attacker assumptions. The scenarios were deliberately designed to span a range of sizes and topologies, from a flat set of independent client hosts to a deep, multi-tier server architecture, allowing the framework's analytical output and dynamic behavior to be examined across environments of increasing complexity. They do not reproduce specific production environments. Instead, they represent recurring architectural and exposure patterns found in organizational infrastructures.

Their representativeness derives from the diversity of security situations they cover. The first scenario represents internet delivered client-side compromise of end-user systems. The second represents a conventional multi-tier web application with an internet-facing reverse proxy, application server, data services and an administrative workstation. The third represents a larger enterprise service architecture with a segmented front end, application tier, identity service, database, cache, message broker and clinician workstation. Together, the scenarios exercise direct exposure, client-side exploitation, lateral movement, tiered network segmentation, protected backend services and assets with different criticality profiles.

Each scenario was represented by simulated input artifacts supplied to the framework. As described in @ch-design, the framework itself was executed on a single host as a set of containerized services orchestrated with Docker Compose. For each experiment, the pipeline processed the corresponding inputs through the full sequence of layers: environment correlation bound vulnerabilities to assets, the orchestrator determined whether regeneration was required and invoked MulVAL, and the post-processing layer enriched, scored and visualized the resulting graph. The persistent threat intelligence database, populated by the ingestion layer from the National Vulnerability Database, EPSS and the CISA KEV catalogue, was shared across all experiments, ensuring that every scenario was scored against the same intelligence snapshot.

A common configuration was applied throughout, so that differences in the results are attributable to the scenarios themselves rather than to parameter changes. The post-processing layer retained the ten highest risk attack paths per run, bounded path enumeration at a maximum depth of thirty (which also serves as a cycle guard), and aggregated up to two hundred paths into the host-level summary graph. Unless explicitly overridden per asset, the global default asset criticality was set to `MEDIUM` and the confidentiality, integrity and availability priorities were left equal, so that the impact multiplier remained neutral in the absence of a deliberate prioritization decision. Where defined, per asset criticality and CIA priorities were specified in the asset mapping file of each scenario.

To keep the analysis tractable and the attack graphs interpretable, the software versions assigned to each asset use explicit version-specific CPEs. Together with the shared database snapshot, these mappings fixed the set of CVEs considered for each scenario in this evaluation. A subsequent intelligence refresh could yield additional CVE mappings for the same CPEs in later executions. The scenarios use real software products identified by CPEs and are enriched with CVE, CVSS, EPSS and KEV data obtained through the pipeline, preserving a grounded mapping between products, identifiers and vulnerabilities. The results therefore demonstrate the operation and comparative prioritization behavior of the framework across representative architectural patterns. Each scenario additionally includes a STRIDE threat model constructed for this study from its defined assets, network connections, exposed services and trust boundaries. The model applies the STRIDE categories systematically to the components of each simulated architecture and translates the identified threats into supplementary MulVAL-compatible logical facts. The resulting models reflect the threat classes relevant to the selected architectural patterns.

For each scenario, the evaluation reports the structure of the generated attack graph, the asset inventory and attacker goals, the host-level summary view produced by the post-processing layer and the ranked set of highest risk attack paths with their associated threat intelligence attributes. The first scenario additionally includes a delta analysis, comparing successive risk reports to quantify how the prioritization responds to a change in the environment or in the underlying intelligence.

// #pagebreak(weak: true)
== Scenario 1: Client-Side Exposure

The first scenario models a common form of initial compromise: client-side exploitation of vulnerable end-user software. It consists of three independent victim hosts, each running a distinct vulnerable client application and each permitted to browse outbound to the internet, where the attacker is located. The hosts do not communicate with one another, so the scenario contains no lateral movement and instead isolates the client-side exploitation primitive. The topology is shown in @fig-scenario1-topology.

#figure(
  image("images/scenario1_topology.png", width: 80%),
  caption: [Scenario 1 topology: three independent victim hosts browsing outbound to an attacker-controlled internet.],
) <fig-scenario1-topology>

The asset inventory comprises `victim1` running Mozilla Firefox 26, `victim2` running ABBYY FineReader 10.0 Pro and `victim3` running Mozilla VPN 2.3. The attacker is located on the internet (`attackerLocated(internet)`) and the analysis goal is to obtain code execution on each host, expressed as `attackGoal(execCode(victimN, _))`. The current CPE mappings yield `CVE-2019-20383` for FineReader and `CVE-2022-0517` for Mozilla VPN. Firefox 26 has no CVE-derived match in the current database snapshot. In line with the conceptual design, the environment correlation layer injected the corresponding `vulExists` and `vulProperty` facts, modeling each matched weakness as a client-side `remoteClient` exploit with a privilege escalation consequence. The STRIDE model contributed one additional Elevation of Privilege threat per host, each mapped to the MITRE ATT&CK technique T1203 (Exploitation for Client Execution).

MulVAL generated an attack graph of 44 nodes and 59 edges, of which 15 are leaf nodes and 5 are vulnerability leaves, drawn from 2 unique CVEs. The post-processing layer enumerated 81 distinct root-to-leaf attack paths and achieved full enrichment coverage, meaning that every CVE node was successfully matched against threat intelligence data. The raw attack graph generated by MulVAL is available as the #link("https://github.com/eduardoascunha/dynamic-attack-graph-framework/blob/main/src/test_cases/scenario1/gen_graph/AttackGraph.pdf")[original `AttackGraph.pdf`] in the project repository. The detailed annotated graph shown in @fig-scenario1-annotated is also available as the #link("https://github.com/eduardoascunha/dynamic-attack-graph-framework/blob/main/src/test_cases/scenario1/post_processing/AttackGraph_annotated.png")[annotated `AttackGraph_annotated.png`] in the project repository, allowing its labels and annotations to be inspected at full resolution.

#figure(
  image("images/scenario1_annotated.png", width: 100%),
  caption: [Scenario 1 detailed annotated attack graph produced by the post-processing layer, with nodes coloured by computed risk level.],
) <fig-scenario1-annotated>

The condensed host-level summary produced for this scenario is shown in @fig-scenario1-summary. It provides a compact view of each host's exposure and worst-case path risk.

#figure(
  image("images/scenario1_summarized.png", width: 80%),
  caption: [Scenario 1 host-level summary graph: each victim is reached directly from the internet, annotated with its worst-case path risk and exploited CVEs.],
) <fig-scenario1-summary>

The summary view communicates the relative exposure of the three hosts. All three are reachable directly from the internet. `victim2` carries the highest worst case path risk at $0.04$ when rounded for visualization, `victim3` follows at $0.01$ and `victim1` remains at $0.00$.

The risk value on each arrow quantifies only the path fragments that establish reachability between the attacker and a host, whereas the value inside a host is the maximum risk of a complete attack path that reaches it. In Scenario 1, every arrow from the internet represents initial network reachability and no vulnerability is traversed in the corresponding path fragment, so its risk is $0.00$. The vulnerability is exploited after that step, and its contribution is reflected in the risk value displayed inside the corresponding host node.

Although reachability is identical for all three hosts, threat intelligence differentiates their risks. The highest ranked path is driven by `CVE-2019-20383` on `victim2`, with CVSS $7.8$ and EPSS $0.0048$. `CVE-2022-0517` on `victim3` has the same CVSS score but EPSS $0.00185$, so its path risk is lower. The STRIDE fact on `victim1` remains structurally represented but lacks CVE enrichment, so its paths score zero.

=== Delta Analysis: Stable Baseline

Each run produces a risk report and a delta report. The risk report records the graph version, structural summary and ranked paths, while the delta report compares it with the preceding report. @lst-scenario1-risk-report shows the beginning of the current risk report.

#figure(
```json
{
  "graph_version": "8c9799948c0633aa",
  "summary": {
    "total_nodes": 44,
    "total_leaf_nodes": 15,
    "total_vulnerability_leaf_nodes": 5,
    "unique_cves": 2,
    "total_attack_paths": 81,
    "enrichment_coverage_pct": 100.0
  },
  "top_attack_paths": [
    {
      "path_id": "05edc12ff37343b4",
      "goal": "execCode(victim2,user)",
      "risk_score": 0.0375,
      "path_length": 3,
      "leaf_cves": ["CVE-2019-20383"],
      "highest_risk_vuln": "CVE-2019-20383",
      "kev_on_path": false,
      "max_epss": 0.0048,
      "max_cvss": 7.8
    }
  ]
}
```,
  caption: [Scenario 1 risk report.],
) <lst-scenario1-risk-report>

The most recent repeated execution is unchanged and produces an empty delta, establishing a reproducible baseline. A synthetic example in @lst-scenario1-delta-report illustrates a contextual update in which `CVE-2019-20383` is added to the KEV catalogue.

#figure(
```json
{
  "previous_version": "8c9799948c0633aa",
  "current_version": "8c9799948c0633aa",
  "vulnerability_delta": {
    "new_cves": [],
    "removed_cves": []
  },
  "risk_change": {
    "average_top_path_score_delta": 0.0053,
    "new_top_paths": [],
    "removed_top_paths": []
  },
  "kev_additions": ["CVE-2019-20383"]
}
```,
  caption: [Synthetic Scenario 1 delta report for a contextual KEV update.],
) <lst-scenario1-delta-report>

Because this change affects no scenario facts, both graph versions are identical. The KEV update increases the average top path risk by $0.0053$ without changing the ranking. When a CPE mapping adds or removes a `vulExists` fact, the orchestrator detects the structural change and regenerates the graph before post-processing compares the resulting report with the archived baseline.

== Scenario 2: Multi-Tier E-commerce Deployment

The second scenario increases both the size and the architectural depth of the environment, modeling a moderately sized multi-tier e-commerce deployment. An internet-facing nginx reverse proxy in a @dmz fronts a Magento (Adobe Commerce) storefront, which is in turn backed by a MariaDB database and a Redis cache in a protected data tier. A back-office administrator workstation browses outbound to the internet, introducing a parallel client-side attack surface. Unlike the first scenario, this environment contains lateral movement, as network reachability rules permit an attacker to pivot from the proxy to the application server and from there into the data tier. The topology is shown in @fig-scenario2-topology.

#figure(
  image("images/scenario2_topology.png", height: 65%),
  caption: [Scenario 2 topology: a multi-tier e-commerce deployment with a DMZ proxy, an application server, a data tier and a back-office workstation.],
) <fig-scenario2-topology>

The attacker originates on the internet, and a code execution goal is declared for every host, allowing the framework to reason about the full set of reachable objectives rather than a single target. The per asset criticality and the confidentiality, integrity and availability priorities that drive the risk scoring are summarized in @tab-scenario2-priorities. Criticality was raised to `HIGH` for the internet-facing and data bearing hosts, with the cache server retained at `MEDIUM`, while the CIA priorities were tuned per asset to reflect differing security concerns, for instance favouring confidentiality on the database and availability on the internet-facing proxy.

#figure(
  table(
    columns: (1.6fr, 1.1fr, 0.7fr, 0.7fr, 0.7fr),
    inset: 6pt,
    align: left + horizon,
    stroke: (x, y) => if y == 0 { (bottom: 1pt + black) } else { (bottom: 0.5pt + gray) },
    fill: (col, row) => if row == 0 { gray.lighten(80%) },
    table.header(
      [*Asset*], [*Criticality*], [*C*], [*I*], [*A*],
    ),
    [webProxy], [HIGH], [MEDIUM], [HIGH], [HIGH],
    [appServer], [HIGH], [HIGH], [HIGH], [HIGH],
    [dbServer], [HIGH], [HIGH], [HIGH], [MEDIUM],
    [cacheServer], [MEDIUM], [MEDIUM], [MEDIUM], [MEDIUM],
    [adminWorkstation], [HIGH], [HIGH], [MEDIUM], [LOW],
  ),
  caption: [Scenario 2: per asset criticality and confidentiality (C), integrity (I) and availability (A) priorities.],
) <tab-scenario2-priorities>

MulVAL produced a graph of 82 nodes and 125 edges, with 37 leaf nodes, 25 vulnerability leaves and 19 unique CVEs. The post-processing layer enumerated 1373 attack paths. All CVE identities were enriched, and every current CVE match carried the CVSS data needed to calculate a numeric path score. The raw attack graph generated by MulVAL is available as the #link("https://github.com/eduardoascunha/dynamic-attack-graph-framework/blob/main/src/test_cases/scenario2/gen_graph/AttackGraph.pdf")[original `AttackGraph.pdf`] in the project repository. The detailed annotated graph shown in @fig-scenario2-annotated is also available as the #link("https://github.com/eduardoascunha/dynamic-attack-graph-framework/blob/main/src/test_cases/scenario2/post_processing/AttackGraph_annotated.png")[annotated `AttackGraph_annotated.png`] in the project repository, allowing its labels and annotations to be inspected at full resolution.

#figure(
  image("images/scenario2_annotated.png", width: 100%),
  caption: [Scenario 2 detailed annotated attack graph produced by the post-processing layer, with nodes coloured by computed risk level.],
) <fig-scenario2-annotated>

The condensed host-level summary, shown in @fig-scenario2-summary, captures the chained nature of the environment: the attacker reaches `webProxy` from the internet, pivots to `appServer` and then fans out to the `dbServer` and `cacheServer` backends. The `adminWorkstation` contributes a STRIDE derived client-side threat, but its Firefox ESR CPE has no CVE match in the current intelligence snapshot. It therefore does not contribute a CVE-based risk path in this run. The summary abstracts away individual reasoning steps while retaining attacker movement and risk concentration across the environment.

#figure(
  image("images/scenario2_summarized.png", width: 100%),
  caption: [Scenario 2 host-level summary graph: lateral movement from the DMZ proxy through the application server into the data tier, with a separate workstation threat path.],
) <fig-scenario2-summary>

A salient feature of the host-level summary graph developed in this work is the path count annotation added to each lateral movement edge. It reports how many of the selected attack paths traverse that host-to-host transition, exposing the bottlenecks of the modeled environment. The transition from `webProxy` to `appServer` is traversed by 189 paths. The onward transitions to the database and cache carry 105 and 72 paths respectively, identifying the application server as the central pivot for movement into the data tier. This information is operationally valuable: hardening or segmenting the application tier would invalidate a disproportionate share of the attack paths, an insight that the flat reachability view of a conventional attack graph does not surface.

The highest numeric path risk in this scenario is $0.3584$, driven by `CVE-2026-44170` on the MariaDB server. This CVE has a CVSS base score of $9.8$ and an EPSS score of $0.01704$. It is followed closely by `CVE-2026-49261`, also on MariaDB, with CVSS $9.8$, EPSS $0.01691$ and path risk $0.3557$. The highest cache path is driven by `CVE-2026-25243`, with CVSS $8.8$, EPSS $0.03663$ and path risk $0.3228$. None of the correlated CVEs is present in the KEV catalogue. The framework therefore distinguishes the larger structural exposure from the relatively low exploitation probabilities in the current intelligence snapshot. Were any EPSS score to rise, the same structural graph would be re-scored upward without regeneration.

== Scenario 3: Enterprise Healthcare Information System

The third scenario represents the most structurally complex environment evaluated, modeling an enterprise hospital information system. An internet-facing HAProxy load balancer terminates TLS and fronts an Apache Tomcat portal, which calls an Eclipse Jetty REST API. The API authenticates against a Keycloak identity provider and is backed by a PostgreSQL database, a Memcached cache and a RabbitMQ message broker carrying HL7 clinical events. A clinician workstation reads external email, providing a client-side entry vector. With eight hosts arranged across five tiers and the API server branching into four backend services, this is the most complex case among the evaluated scenarios for the correlation logic and path enumeration stage. The topology is shown in @fig-scenario3-topology.

#figure(
  image("images/scenario3_topology.png", width: 80%),
  caption: [Scenario 3 topology: an eight-host healthcare information system with a DMZ load balancer, an application tier, an identity provider, a data tier and a clinician workstation.],
) <fig-scenario3-topology>

A code execution goal was declared for all eight hosts. As in the previous scenario, criticality was assigned per asset, with the internet-facing, application, identity and data bearing hosts marked `HIGH` and the cache and message broker hosts retained at `MEDIUM`. The STRIDE model for this scenario is the richest of the three, contributing eight threats spanning Tampering, Spoofing, Information Disclosure and Elevation of Privilege, each mapped to a corresponding MITRE ATT&CK technique and translated into supplementary logical facts.

The generated attack graph comprises 153 nodes and 246 edges, with 71 leaf nodes, 53 vulnerability leaves and 45 unique CVEs. Path enumeration yielded 14204 distinct attack paths, the largest of the three scenarios. All CVE identities were enriched, but `CVE-2026-12611`, `CVE-2026-19203` and `CVE-2026-19204` on Jetty have no CVSS score or vector in the current data source. They produce 114 paths with undefined risk, which are deliberately placed first in the risk report for manual review. The raw attack graph generated by MulVAL is available as the #link("https://github.com/eduardoascunha/dynamic-attack-graph-framework/blob/main/src/test_cases/scenario3/gen_graph/AttackGraph.pdf")[original `AttackGraph.pdf`] in the project repository. The detailed annotated graph is reproduced in @app-graphs and is also available as the #link("https://github.com/eduardoascunha/dynamic-attack-graph-framework/blob/main/src/test_cases/scenario3/post_processing/AttackGraph_annotated.png")[annotated `AttackGraph_annotated.png`] in the project repository, allowing its labels and annotations to be inspected at full resolution. Only the host-level summary, shown in @fig-scenario3-summary, is presented here.

#figure(
  image("images/scenario3_summarized.png", width: 100%),
  caption: [Scenario 3 host-level summary graph: deep lateral movement from the DMZ to the API server, which fans out into the identity and data tiers.],
) <fig-scenario3-summary>

The summary graph presents this evaluated environment in a compact form. The attack progresses from `portalServer` to `apiServer`, which then branches to the four backend services. The edge labels record 85 paths from the portal to the API. The onward transitions from the API to the database, cache, identity provider and message broker carry 130, 36, 12 and 9 paths respectively. The API to database transition is the most frequent lateral movement in the summary, reflecting the broad branching of the application tier. The undefined Jetty paths are retained for review but are not assigned fabricated numeric scores. The highest numerically scored paths, summarized in @tab-scenario3-paths, are driven by `CVE-2023-24998` on the Tomcat portal. It has a CVSS base score of $7.5$, an EPSS score of $0.48788$ and no KEV status.

#figure(
  table(
    columns: (0.6fr, 1.9fr, 0.7fr, 0.8fr, 1.5fr, 0.7fr, 0.7fr, 0.6fr),
    inset: 6pt,
    align: left + horizon,
    stroke: (x, y) => if y == 0 { (bottom: 1pt + black) } else { (bottom: 0.5pt + gray) },
    fill: (col, row) => if row == 0 { gray.lighten(80%) },
    table.header(
      [*Rank*], [*Goal*], [*Risk*], [*Length*], [*Primary CVE*], [*CVSS*], [*EPSS*], [*KEV*],
    ),
    [1], [execCode(portalServer, tomcat)], [3.66], [3], [CVE-2023-24998], [7.5], [0.488], [no],
    [2], [execCode(apiServer, jetty)], [3.37], [7], [CVE-2023-24998], [7.5], [0.488], [no],
    [3], [execCode(dbServer, postgresql)], [3.25], [11], [CVE-2023-24998], [7.5], [0.488], [no],
  ),
  caption: [Scenario 3: representative highest numerically scored attack paths and their threat intelligence drivers. Paths without CVSS are excluded from this numerical ranking.],
) <tab-scenario3-paths>

The decreasing risk along the numeric ranking is a direct consequence of the directness factor $d(P)$ defined earlier in the scoring model. The portal goal, reached in 3 steps, is scored higher than the 11 step path to the database driven by the same vulnerability. Because $d(P) = 1 / log_2(|P| + 2)$ decreases as a path lengthens, the same driver vulnerability necessarily yields a higher score on the shorter path. This is an arithmetic property of the scoring formula rather than a separate heuristic, yet it still lets the framework differentiate between paths that share an exploitation driver but differ in depth, supporting prioritization in deep architectures.

== Comparative Discussion

The case studies allow the proposed framework to be contrasted with a conventional, static use of MulVAL and related to the objectives stated in Chapter 1. This comparison clarifies how the proposed pipeline extends structural reachability analysis with dynamic threat intelligence.

A conventional invocation of an attack graph generator answers a structural question: given a network configuration and a set of vulnerabilities, which hosts can the attacker reach and through which exploit chains? This is valuable but incomplete. MulVAL adapters can supply later invocations with refreshed vulnerability repository data or scanner output, but each invocation still reasons over the particular fact base that it receives. On their own, these updates do not determine whether refreshed information is relevant to a specific environment or separate a structural change from a contextual change. Independently, threat modeling outputs are not translated into facts that can influence automated attack graph generation. The proposed framework addresses both limitations. Across all three scenarios, the unannotated attack graph shows which attack paths are feasible, but it does not establish which vulnerability, path or asset should be remediated first. Enriching and scoring the same graph provides a risk-based prioritization. In Scenario 1 the three equally reachable victims separate into distinct low-risk scores according to the estimated exploitation likelihood of their vulnerabilities, while the host without a matched CVE receives zero CVE risk. Separately, the host-level summary graph aggregates selected attack paths by host. It identifies the application server as the bottleneck through which most selected paths pass in Scenario 2 and the API server as the dominant pivot into the protected tiers in Scenario 3. These latter observations arise from the summarized path structure, whereas the Scenario 1 distinction is driven by threat intelligence.

The framework also addresses the evolution of risk over time. An individual graph is necessarily a snapshot, but the implementation supports repeated correlation, selective regeneration and contextual rescoring. It compares normalized scenario facts to determine whether regeneration is required, while intelligence signals and asset criticality are applied during post-processing.

These results map directly to the objectives defined in Chapter 1. The end-to-end operation of the layered pipeline across three environments realizes the conceptual and architectural model linking dynamic threat intelligence and structured threat modeling outputs to attack graphs (Objective 1) and is underpinned by the automated ingestion and correlation of CVE, CVSS, EPSS and KEV intelligence (Objective 2). The translation of the STRIDE models into MulVAL facts, together with the implemented change detection and post-processing mechanisms, provides the basis for adaptive model evolution and re-prioritization (Objective 3). The detailed annotated graphs, host-level summary graphs, ranked path tables and risk reports transform the enriched models into actionable analytical insight (Objective 4). Finally, the three case studies validate the framework's functional behavior and analytical usefulness in representative scenarios (Objective 5). Collectively, the evidence indicates that the framework achieves its central aim of advancing attack graphs from static representations into dynamic, intelligence-driven decision support tools.

== Chapter Summary

This chapter evaluated three increasingly complex network scenarios. The pipeline generated enriched attack graphs, ranked paths using CVSS, EPSS, KEV status and asset criticality, and produced detailed and host-level views.

These findings show how the approach extends static reachability analysis with current threat context and selective recomputation. The final chapter summarizes the contributions, assesses the objectives and outlines future work.

= Conclusion and Future Work <ch-conclusion>

This dissertation addressed the broader problem of maintaining useful attack graph analyses as environments, threat intelligence and threat-modeling assumptions evolve. A conventional MulVAL execution reasons over the fact base supplied to it, but does not by itself correlate refreshed intelligence with a specific environment, distinguish structural changes from changes in risk context or translate threat-modeling outputs into facts for automated reasoning. The work therefore proposed, implemented and evaluated a framework that combines CPE-based environment correlation, STRIDE-to-MulVAL translation, selective graph regeneration and contextual path-risk scoring.

The proposed solution is realized as a modular, event-driven pipeline of containerized services built around the MulVAL logical reasoning engine. It complements MulVAL's existing adapters by correlating intelligence with a CPE-based asset inventory, enabling analysis where vulnerability scans cannot be performed or are inappropriate. A persistent threat intelligence knowledge base is populated from authoritative sources, namely CVE and CPE records, CVSS severity metrics, EPSS exploitation probabilities and the CISA KEV catalogue. An environment correlation layer binds this intelligence to the modeled infrastructure and, in the same stage, translates the STRIDE threat model into logical facts, together producing the enriched fact base that MulVAL consumes. A central design decision underpins the entire framework: the interaction rules remain fixed while only the fact base evolves, which preserves compatibility with existing MulVAL rule sets and the favorable inference properties of the engine, while confining all adaptive behavior to the surrounding layers. An orchestration layer compares normalized scenario facts and regenerates the graph when they change; it otherwise reuses the existing graph. A post-processing layer enriches and scores the graph, compares reports and produces annotated and host-level visualizations. The case studies in @ch-evaluation demonstrated that this architecture operates end to end across environments of increasing complexity.

== Summary of Contributions

The following summary describes how the design, implementation and evaluation presented in the preceding chapters realize the contributions defined in @sec-objectives.

First, the work delivers a dynamic integration of threat intelligence into attack models. Each generated attack graph remains a snapshot of its input facts, but the framework relates successive snapshots to evolving threat data by correlating vulnerability disclosures, severity metrics, exploitation probabilities and confirmed exploitation signals with the model's fact base. The case studies confirmed that this enrichment transforms an undifferentiated reachability picture into a justified prioritization, separating equally reachable targets according to the likelihood and impact of their underlying vulnerabilities.

Second, the work realizes mechanisms for adaptive model evolution and re-prioritization. The orchestrator's two-phase change detection strategy regenerates the attack graph when normalized scenario facts change, while the post-processing scorer is designed to re-rank attack paths when an intelligence signal, such as a revised EPSS score or a newly catalogued KEV entry, is updated.

Third, the work provides a practical mechanism for integrating threat modeling with automated attack graph generation. The STRIDE model is validated against the modeled assets, and its threat categories and declared impacts are translated into logical facts consumable by MulVAL. This permits adversarial assumptions from qualitative threat modeling to participate in attack path generation alongside concrete vulnerability facts.

Taken together, the contributions establish an end-to-end method for incorporating evolving threat intelligence into logical attack graph analysis. The evaluation confirms that the framework can correlate vulnerability and threat modeling data with a modeled environment, distinguish structural changes from contextual risk updates, and present the resulting priorities through reports and host-level summaries. These results support its use as a research prototype for dynamic attack graph maintenance

== Future Work

While the framework achieves its stated objectives, several avenues remain open for extending its expressiveness, usability and analytical depth. The following directions focus on capabilities that would broaden its intelligence inputs and operational usefulness.

=== Richer cyber threat intelligence ingestion

The current ingestion layer consumes vulnerability-centric intelligence (CVE, CVSS, EPSS and KEV). A natural extension is to incorporate structured CTI expressed in standards such as STIX, enabling the framework to reason about threat actors, campaigns, malware and tactics, techniques and procedures. Integrating this richer, relationship-oriented intelligence would allow adversary context to inform attack-path prioritization and bring the model closer to genuine intelligence-driven decision making. The ingestion layer was deliberately designed to be extensible to such formats without affecting the downstream reasoning stages.

=== Adoption of CVSS 4.0

The scoring model currently derives vulnerability severity from the CVSS v3.1 base score, falling back to v3.0 when the former is unavailable. Since the release of CVSS 4.0, which refines the base metrics and introduces threat and supplemental dimensions better aligned with real-world exploitation, incorporating the version 4.0 score into the base risk computation would sharpen the severity signal and keep the framework aligned with the current standard. In such an extension, the v3.x scores would still need to be retained for the many vulnerabilities not yet rescored under 4.0, preserving coverage during the ongoing transition between versions.

=== Richer exploit consequences

The current translation represents all correlated vulnerabilities as privilege escalation events because it preserves MulVAL's standard interaction rules. Extending the framework to model data disclosure, data modification and service disruption as distinct logical consequences would require corresponding predicates and interaction rules, together with an extended translation layer. The CVSS confidentiality, integrity and availability ratings alone are insufficient to determine the concrete outcome of an exploit, so such a translation would require additional vulnerability semantics or analyst validation. This extension would allow the attack graph to capture goals other than code execution without treating every successful exploit as an escalation of privilege.

=== Automated translation of threat models

At present, the STRIDE threat model must be supplied to the framework as a structured JSON template, which the analyst authors by hand. A natural extension is to let the analyst keep performing the STRIDE analysis in their usual narrative form and to use a language model to translate that report into the JSON template the pipeline consumes, mapping the assets, threats, categories and impacts to its machine-readable schema. In its minimal form this is a well-scoped translation task that already lowers the barrier to adoption. The same mechanism could later be extended so that the model also assists with the analysis itself, for instance by suggesting candidate threats or impacts for the analyst to review.

=== Risk-threshold filtering and risk acceptance

Two analyst-facing controls would make the output more actionable in day-to-day operations. The first is a configurable risk threshold: by specifying a minimum score, an analyst could restrict the generated graph and the reports to attack paths whose risk exceeds that value, for example suppressing everything below a score of 3.0 so that only the more pressing exposures are shown. The second is explicit risk acceptance, which would let an analyst mark specific vulnerabilities, paths or assets as accepted, so that known false positives or consciously tolerated risks are excluded from the prioritization rather than resurfacing on every run. Together these controls would focus the framework's attention on the risks an organization actually intends to act upon.

=== Graceful handling of the no-attack-path outcome

When MulVAL derives no attack path to any goal, the pipeline currently treats the result as a failure: the orchestrator exits with an error and the post-processing stage is skipped, so no report is produced. The absence of a reachable attack path is, however, a legitimate and often desirable outcome, and it does not imply that the environment is free of risk. Individual assets may still carry vulnerabilities that warrant remediation even when no end-to-end path currently chains them into a compromise of the declared goals. A more robust design would treat the empty graph as a first-class success: the pipeline would still run the post-processing stage and emit a report that records the vulnerabilities present on each asset, notes the absence of a viable attack path, and feeds the delta analysis, so that a transition from an exposed to a path-free environment is captured as a positive result rather than a broken run.

=== Scalability evaluation and optimization

The current evaluation verifies functional behavior and selective regeneration, but it does not establish the processing limits of the framework. Future work should measure execution time, memory consumption and output size while systematically varying the number of hosts, services, vulnerabilities and feasible attack paths. The measurements should separate the costs of environment correlation, MulVAL inference, path enumeration and graph rendering.

The current host-level summary improves the readability of dense graphs by presenting only hosts, selected high-risk paths and risk annotations. It does not reduce the cost of generating the detailed graph or enumerating paths. Addressing computational scalability would require investigation of techniques such as incremental logical inference, selective graph generation, bounded or top-ranked path enumeration, and aggregation strategies that are applied before full graph visualization. Some of these approaches may require changes to MulVAL or its interaction rules, while others can be implemented in the surrounding pipeline. A dedicated evaluation is needed to determine which approach is appropriate and to quantify its effect.

=== Operational integration and visualization

Finally, the framework's practical impact would be strengthened by tighter integration with operational security tooling. Connecting it to SIEM platforms would enable observed events and alerts to drive model updates and would allow the resulting prioritization to feed back into operational workflows. In parallel, a dedicated graphical user interface for configuring scenarios, browsing the generated graphs and exploring delta reports would improve usability and make the dynamic, evolving nature of the model more immediately accessible to analysts.

These directions, ranging from richer intelligence sources and more expressive attack modeling to automated threat-model translation, analyst-driven risk filtering, operational robustness, scalability evaluation and integration with security tooling, would further strengthen the framework's analytical and practical capabilities. They also outline a path from the current research prototype toward a more comprehensive operational decision-support capability.


// Bibliografia
#[
  #set heading(numbering: none)

  // Render bibliography
  // Change this to a .bib file if you prefer that format instead
  #bibliography("bibliography.yml", full: true)

  // Render index
  // NOTE: The index is empty because no terms have been tagged with #index[...]
  // in the text. To use it, mark terms throughout the document (e.g. #index[MulVAL])
  // and then uncomment the block below.
  // #set heading(outlined: false)
  // = Index
  // #columns(
  //   2,
  //   make-index(
  //     title: none,
  //     use-page-counter: true,
  //     section-title: (letter, counter) => {
  //       set text(weight: "bold")
  //       block(letter, above: 1.5em)
  //     },
  //   ),
  // )
]

#[
  #counter(heading).update(0)
  #set heading(numbering: "A.1", supplement: [Appendix]) // Change to [Apêndice] for Portuguese

  #include "appendix.typ"
]

#set page(numbering: none)

#page(fill: colors.pantonecoolgray7)[
  #box(width: 0pt, height: 0pt)[]
]

#page[
  #box(width: 0pt, height: 0pt)[]
]
