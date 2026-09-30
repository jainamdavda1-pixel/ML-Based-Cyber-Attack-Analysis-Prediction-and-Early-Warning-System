# ML-Based Cyber Attack Analysis, Prediction & Early Warning System

A beginner-friendly cybersecurity machine-learning project that explores
how labelled network-traffic data can be used to identify suspicious
activity, classify known attack categories, estimate attack risk, and
present findings through a web dashboard.

> **In simple words:** Imagine a security analyst reviewing thousands of
> network connections. Each connection has measurable details, such as
> how long it lasted, how many packets were exchanged, and how much data
> was transferred. This project uses machine-learning models trained on
> labelled examples to recognize patterns that resemble normal traffic
> or known attack categories. The dashboard helps a person review the
> results and decide what to investigate.

**Project type:** Academic/research prototype\
**Main models:** XGBoost classification pipelines for CICIDS2017 and
UNSW-NB15\
**Backend:** Python + FastAPI\
**Frontend:** React + TypeScript\
**Database:** SQLite\
**Important:** This is a decision-support prototype, not a certified
production intrusion-detection system. A prediction is not proof of an
attack. Live monitoring feature extraction is experimental and has not
been validated as benchmark-equivalent.

------------------------------------------------------------------------

## Contents

-   [1. Project overview](#1-project-overview)
-   [2. How the system works](#2-how-the-system-works)
-   [3. Datasets at a glance](#3-datasets-at-a-glance)
-   [4. CICIDS2017 attack categories](#4-cicids2017-attack-categories)
-   [5. UNSW-NB15 attack categories](#5-unsw-nb15-attack-categories)
-   [6. Understanding input features](#6-understanding-input-features)
-   [7. Example: how one record is
    interpreted](#7-example-how-one-record-is-interpreted)
-   [8. Model training and prediction](#8-model-training-and-prediction)
-   [9. Evaluation results](#9-evaluation-results)
-   [10. Risk scoring and early
    warning](#10-risk-scoring-and-early-warning)
-   [11. SHAP explainability](#11-shap-explainability)
-   [12. Application architecture](#12-application-architecture)
-   [13. Current implementation
    status](#13-current-implementation-status)
-   [14. Technology stack](#14-technology-stack)
-   [15. Repository structure](#15-repository-structure)
-   [16. Run locally](#16-run-locally)
-   [17. Run with Docker Compose](#17-run-with-docker-compose)
-   [18. Using the application](#18-using-the-application)
-   [19. API overview and examples](#19-api-overview-and-examples)
-   [20. Model artifacts and datasets](#20-model-artifacts-and-datasets)
-   [21. Testing and validation](#21-testing-and-validation)
-   [22. Troubleshooting](#22-troubleshooting)
-   [23. Limitations and responsible
    use](#23-limitations-and-responsible-use)
-   [24. Future improvements](#24-future-improvements)
-   [25. Beginner glossary](#25-beginner-glossary)

------------------------------------------------------------------------

## 1. Project overview

### The problem

Computer networks carry ordinary activity as well as potentially harmful
activity. Examples include repeated password attempts, port scanning,
attempts to exploit vulnerable software, and traffic intended to
overwhelm a service. Manually reviewing every network record is
difficult.

A machine-learning model can learn patterns from labelled examples and
use those patterns to classify new records. This project connects that
model-based analysis to a web application so users can submit traffic
data and inspect predictions.

### Project objectives

-   Analyze supported network-flow records.
-   Classify traffic as normal or as a known attack category, depending
    on the selected model.
-   Estimate attack likelihood through a separate risk-scoring workflow.
-   Present results, history, risk indicators, and available
    explanations in a dashboard.
-   Explore how machine-learning models can be integrated with a backend
    API and frontend application.
-   Provide a foundation for future temporal early-warning research.

### What does "early warning" mean here?

The current CICIDS2017 risk experiment uses a probability threshold to
raise a warning when estimated attack probability is sufficiently high.
This is a **threshold-based warning**, not a prediction that an attack
will happen in the future.

True future-attack forecasting requires timestamped chronological data,
a clearly defined future event, a trained temporal model, and an
evaluation showing how early and reliably warnings occur. A trained
LSTM/sequence model is **not currently configured** in this repository.

### Who might use the project?

-   **Students:** learn about intrusion-detection datasets, model
    training, evaluation metrics, and full-stack integration.
-   **Researchers:** inspect stored experiment results and compare model
    behavior.
-   **Developers:** study how model inference can be exposed through an
    API and a dashboard.
-   **Security learners:** explore labelled traffic records in a
    controlled, authorized environment.

------------------------------------------------------------------------

## 2. How the system works

The project can be understood as a series of steps:

1.  **Input:** a user submits one flow record, a compatible CSV, or a
    supported traffic capture file.
2.  **Validation:** the backend checks the request and prepares fields
    in the format expected by the selected dataset pipeline.
3.  **Model selection:** the system uses the CICIDS2017 or UNSW-NB15
    pipeline. Their features and labels are separate and must not be
    mixed.
4.  **Prediction:** the selected trained model estimates the most likely
    label or binary normal/attack outcome.
5.  **Risk calculation:** the risk workflow can convert an attack
    probability into a 0--100 score and compare it with a configured
    threshold.
6.  **Storage:** supported prediction and analysis records can be stored
    in SQLite.
7.  **Presentation:** the frontend displays predictions and available
    risk, history, incident, monitoring, or explanation information.
8.  **Human review:** a person checks suspicious results and decides
    whether further investigation is warranted.

### Everyday example

Imagine a web server receiving many connections. A traffic record might
show a short flow, a high number of packets, or an unusual packet rate.
The model compares the combined feature pattern with patterns learned
from its training data. It might predict a denial-of-service-related
label, but that prediction alone does not establish the sender's intent.
An analyst would need to investigate the surrounding traffic and system
context.

------------------------------------------------------------------------

## 3. Datasets at a glance

The project uses two public benchmark datasets for intrusion-detection
research. They are handled by **separate pipelines** because their
feature schemas and label systems differ.

  -----------------------------------------------------------------------
  Item                    CICIDS2017              UNSW-NB15
  ----------------------- ----------------------- -----------------------
  Full name               Canadian Institute for  UNSW-NB15 network
                          Cybersecurity Intrusion intrusion dataset
                          Detection System 2017   
                          dataset                 

  Main purpose here       Multiclass attack       Binary normal/attack
                          classification and a    classification and
                          separate binary risk    multiclass
                          experiment              attack-category
                                                  classification

  Input features used by  70                      42
  the project pipeline                            

  Multiclass output       15                      10
  labels                                          

  Typical normal label    `BENIGN`                `Normal`

  Example attack labels   `DDoS`, `PortScan`,     `DoS`, `Exploits`,
                          `Bot`, DoS and web      `Fuzzers`,
                          attacks                 `Reconnaissance`,
                                                  `Generic`

  Feature schema          No                      No
  compatible with the                             
  other dataset?                                  
  -----------------------------------------------------------------------

**Important:** A 70-feature CICIDS2017 row is not interchangeable with a
42-feature UNSW-NB15 row. Select the correct dataset pipeline and use
the feature definitions and preprocessing associated with that model.

### Where do the datasets come from?

-   CICIDS2017: <https://www.unb.ca/cic/datasets/ids-2017.html>
-   UNSW-NB15: <https://research.unsw.edu.au/projects/unsw-nb15-dataset>

Raw datasets are large and are not included in this repository. See
`data/README.md` for the local project's dataset notes and split-index
information.

------------------------------------------------------------------------

## 4. CICIDS2017 attack categories

The CICIDS2017 multiclass pipeline defines 15 output labels. The
descriptions below are beginner-friendly summaries of the category
names; they do not guarantee that a model prediction is correct.

  --------------------------------------------------------------------------------------
  Label                          Meaning in simple words         Illustrative example
  ------------------------------ ------------------------------- -----------------------
  `BENIGN`                       Traffic labelled as ordinary or A routine connection to
                                 non-attack activity in the      a web service
                                 dataset                         

  `Bot`                          Traffic associated with bot or  A compromised device
                                 botnet activity                 making automated
                                                                 connections

  `DDoS`                         Distributed Denial of Service;  Many devices flood a
                                 many sources send traffic       server with requests
                                 toward a target to overwhelm it 

  `DoS GoldenEye`                A specific denial-of-service    Traffic pattern
                                 attack category in CICIDS2017   associated with the
                                                                 GoldenEye DoS tool

  `DoS Hulk`                     A specific high-volume HTTP     Repeated HTTP requests
                                 denial-of-service category      intended to exhaust a
                                                                 web server

  `DoS Slowhttptest`             A slow-rate DoS category that   Connections send HTTP
                                 attempts to keep connections    data slowly to consume
                                 occupied                        server resources

  `DoS slowloris`                A slow HTTP denial-of-service   Connections remain open
                                 technique                       by sending incomplete
                                                                 HTTP requests slowly

  `FTP-Patator`                  FTP                             Repeated attempts to
                                 password-guessing/brute-force   log in to an FTP
                                 activity                        service

  `Heartbleed`                   Traffic associated with the     A crafted request
                                 Heartbleed vulnerability in     attempts to read
                                 certain OpenSSL versions        unintended memory

  `Infiltration`                 Dataset-specific label for      Activity labelled as
                                 traffic associated with         infiltration in the
                                 infiltration activity           dataset

  `PortScan`                     Attempts to discover available  A source probes many
                                 ports or services on a host     destination ports

  `SSH-Patator`                  SSH                             Repeated login attempts
                                 password-guessing/brute-force   against an SSH service
                                 activity                        

  `Web Attack – Brute Force`     Repeated attempts to guess web  Many login attempts
                                 application credentials         against a web form

  `Web Attack – SQL Injection`   Requests that attempt to        Input containing SQL
                                 manipulate a database query     syntax sent to a
                                 through a vulnerable web        vulnerable form
                                 application                     

  `Web Attack – XSS`             Cross-site scripting attempts   A request attempts to
                                 that try to inject script into  insert JavaScript into
                                 a web page                      a page
  --------------------------------------------------------------------------------------

### A note about labels

A label is the category assigned by the dataset or model. It is not a
complete explanation of the event, proof of malicious intent, or a
severity rating. Some attack names refer to specific tools or
experimental scenarios used while creating the dataset.

------------------------------------------------------------------------

## 5. UNSW-NB15 attack categories

The UNSW-NB15 multiclass pipeline defines 10 labels: one normal-traffic
class and nine attack categories.

  -----------------------------------------------------------------------
  Label                   Meaning in simple words Illustrative example
  ----------------------- ----------------------- -----------------------
  `Normal`                Traffic labelled as     A typical connection
                          ordinary activity       between a client and
                                                  server

  `Analysis`              Dataset category        Traffic that matches
                          covering certain        the dataset's analysis
                          analysis/probing        label
                          activities              

  `Backdoor`              Activity associated     A connection pattern
                          with a hidden or        linked to backdoor
                          unauthorized way to     behavior
                          access a system         

  `DoS`                   Denial of Service;      A target receives
                          activity intended to    traffic that consumes
                          make a service          its resources
                          unavailable             

  `Exploits`              Activity attempting to  A request attempts to
                          take advantage of a     trigger a vulnerable
                          software or             service
                          configuration weakness  

  `Fuzzers`               Activity involving      Many specially formed
                          unusual or varied       inputs are sent to a
                          inputs, often used to   service
                          test software responses 

  `Generic`               A broad                 Traffic grouped under
                          dataset-specific attack the dataset's generic
                          category rather than    attack label
                          one single named        
                          technique               

  `Reconnaissance`        Information gathering   Probing hosts or
                          before or during an     services to learn what
                          attack                  is available

  `Shellcode`             Activity associated     Traffic linked to an
                          with shellcode, small   exploit payload
                          code used in some       
                          exploit techniques      

  `Worms`                 Activity associated     A worm-like pattern
                          with self-propagating   attempting to spread
                          malicious software      between systems
  -----------------------------------------------------------------------

### Binary versus multiclass UNSW-NB15 models

The repository includes two UNSW-NB15 XGBoost artifacts for different
tasks:

-   **Binary model:** predicts whether a record is normal or attack.
-   **Multiclass model:** predicts one of the dataset's 10 labels.

These are different tasks. Binary attack probability should not be
confused with a 10-class probability distribution.

------------------------------------------------------------------------

## 6. Understanding input features

A **feature** is one measurable piece of information about a network
flow. The model does not understand a network connection in the same way
a person does; it uses numeric patterns in the input features.

Examples of common network-flow feature groups are shown below. Exact
column names vary by dataset, and the list below is explanatory---not a
substitute for the complete schema expected by a model.

  ------------------------------------------------------------------------------------
  Feature group      Example field or concept   What it describes    Simple example
  ------------------ -------------------------- -------------------- -----------------
  Endpoint           Source IP, destination IP  Where traffic        Client A
  information                                   originated and where communicates with
                                                it was going, when   Server B
                                                available in the     
                                                source data          

  Port information   Destination port           The service or       Port 80 is
                                                application endpoint commonly used for
                                                being contacted      HTTP

  Protocol           TCP, UDP, ICMP or encoded  The                  A browser
                     protocol value             transport/network    connection
                                                protocol involved    commonly uses TCP

  Flow duration      `Flow Duration`            How long the flow    A flow lasting 2
                                                lasted, usually in a seconds
                                                dataset-defined unit 

  Packet counts      `Total Fwd Packets`,       Number of packets in 8 packets forward
                     `Total Backward Packets`   each direction       and 6 backward

  Byte counts        Forward/backward total     Amount of data       Client sends
                     length                     exchanged in each    1,200 bytes and
                                                direction            receives 4,500
                                                                     bytes

  Packet length      Minimum, maximum, mean or  Whether packets tend A flow has many
  statistics         standard deviation of      to be small, large,  similarly sized
                     packet sizes               or variable in size  packets

  Flow rates         Bytes per second or        How quickly data or  A high packet
                     packets per second         packets are          rate over a short
                                                exchanged            period

  Timing             Inter-arrival time (IAT)   Time gaps between    Packets arrive at
                     statistics                 packets              regular intervals
                                                                     or in bursts

  TCP flags          SYN, ACK, FIN, RST-related Aspects of TCP       Many connection
                     counts or flags            connection setup,    attempts that do
                                                acknowledgement,     not complete
                                                closure, or reset    normally
                                                behavior             

  Directional        Forward versus backward    Differences between  Much more data
  statistics         packet/byte measures       traffic sent and     sent than
                                                traffic received     received

  Dataset-specific   Fields defined only in one Additional           A field present
  fields             dataset                    measurements         in UNSW-NB15 but
                                                produced by that     absent from
                                                dataset's            CICIDS2017
                                                feature-extraction   
                                                method               
  ------------------------------------------------------------------------------------

### Why exact feature names and units matter

A model expects the same feature definitions, column order or
named-column mapping, numeric types, units, and preprocessing that were
used when it was trained. For example, a duration measured in
microseconds is not the same value as a duration measured in seconds.

A CSV can look reasonable to a human and still be incompatible with a
model. Use the matching dataset's original or correctly reproduced
feature schema.

### Input dimensions: what does `N × F` mean?

-   `N` means the number of records/rows.
-   `F` means the number of input features per record.

  Input                  CICIDS2017 feature matrix   UNSW-NB15 feature matrix
  -------------------- --------------------------- --------------------------
  One flow record                         `1 × 70`                   `1 × 42`
  100 flow records                      `100 × 70`                 `100 × 42`
  1,000 flow records                   `1000 × 70`                `1000 × 42`

For a 15-class CICIDS2017 multiclass prediction, the model can produce a
probability for each of the 15 labels for every input row. Conceptually,
100 rows can yield a `100 × 15` probability matrix. For a 10-class
UNSW-NB15 multiclass prediction, 100 rows can yield a `100 × 10`
probability matrix.

A binary model has two classes, so its class-probability output has two
class probabilities per row when the model/API exposes the full
probability vector.

### Example feature record (illustrative only)

This example shows the *idea* of a feature record, not a complete
model-ready request:

  ------------------------------------------------------------------------
  Feature                         Illustrative value How to read it
  --------------------- ---------------------------- ---------------------
  Destination port                              `80` The destination
                                                     service port

  Flow duration                            `2000000` Example duration
                                                     value; the unit must
                                                     match the selected
                                                     dataset

  Total forward packets                          `8` Number of packets in
                                                     the forward direction

  Total backward                                 `6` Number of packets in
  packets                                            the reverse direction

  Total forward bytes                         `1200` Example amount of
                                                     forward data

  Total backward bytes                        `4500` Example amount of
                                                     reverse data
  ------------------------------------------------------------------------

**These values are invented for explanation.** They do not represent a
real attack, are not a complete feature set, and should not be submitted
as if they were a valid model input. A real record must include every
required feature with the expected names and preprocessing.

------------------------------------------------------------------------

## 7. Example: how one record is interpreted

Suppose a compatible traffic record contains:

-   a destination port,
-   a flow duration,
-   forward and backward packet counts,
-   byte totals,
-   packet-rate and timing statistics,
-   TCP-related measurements.

The model evaluates the complete feature pattern. It does not decide
that a connection is an attack merely because one field looks unusual. A
high packet rate, for example, may occur during legitimate activity as
well as an attack.

A prediction workflow could look like this:

``` text
Input flow record
      |
      v
Validate required features
      |
      v
Select the correct dataset pipeline
      |
      v
Run the trained XGBoost model
      |
      v
Predicted class + available probabilities
      |
      v
Optional risk calculation and persistence
      |
      v
Show the result for human review
```

The exact result depends on the selected dataset/model, the feature
values, and the model's learned patterns. This README does not assign a
predicted label to the illustrative values above because they are
incomplete and synthetic.

------------------------------------------------------------------------

## 8. Model training and prediction

### What is XGBoost?

XGBoost is a tree-based machine-learning method. It builds a sequence of
decision trees, where later trees try to improve on errors made by the
earlier ones.

A decision tree can be thought of as a set of learned questions, such as
whether a value is above or below a threshold. A real model uses many
such splits and combines their outputs; it does not rely on one manually
written rule.

### Typical training workflow

1.  **Load labelled data:** each row has features and a known target
    label.
2.  **Clean and prepare:** handle data types, invalid values, target
    labels, and feature columns.
3.  **Split the data:** separate training data from validation and
    held-out testing data.
4.  **Train the model:** let XGBoost learn relationships between input
    features and labels.
5.  **Tune parameters:** test settings such as tree depth, number of
    estimators, learning rate, and sampling.
6.  **Evaluate:** use held-out data to calculate metrics and inspect
    class-wise errors.
7.  **Save artifacts:** store the trained model and the label-encoding
    information needed to map predictions back to readable labels.
8.  **Integrate:** load the saved artifact in the backend and use it for
    inference.

### Binary and multiclass learning

  -----------------------------------------------------------------------
  Task                    Question answered       Example output
  ----------------------- ----------------------- -----------------------
  Binary classification   "Does this record       `Normal` or `Attack`
                          belong to the normal or 
                          attack class?"          

  Multiclass              "Which supported label  `BENIGN`, `DDoS`,
  classification          best matches this       `PortScan`, or another
                          record?"                CICIDS2017 class

  Threshold-based risk    "Is the estimated       Risk score and warning
  warning                 attack probability      indicator
                          above the configured    
                          warning cutoff?"        
  -----------------------------------------------------------------------

A multiclass prediction and a binary risk warning may use related model
outputs, but they are not the same evaluation task.

------------------------------------------------------------------------

## 9. Evaluation results

Metrics describe performance on a particular evaluation dataset and
experiment. They do not guarantee the same performance on new networks,
different feature extraction, or live traffic.

### Metric definitions

  -----------------------------------------------------------------------
  Metric                  Meaning in simple words Why it matters
  ----------------------- ----------------------- -----------------------
  Accuracy                Percentage of all       Useful overall, but can
                          predictions that were   hide rare-class
                          correct                 failures

  Precision               Of the records          Low precision means
                          predicted as attacks/a  more false alarms
                          class, how many were    
                          correct                 

  Recall                  Of the actual attacks/a Low recall means more
                          class, how many were    missed attacks
                          found                   

  F1-score                A combined measure of   Useful when both false
                          precision and recall    alarms and missed
                                                  attacks matter

  Macro average           Calculates a metric for Highlights performance
                          each class, then        on small classes
                          averages classes        
                          equally                 

  Weighted average        Averages class metrics  Large classes influence
                          while weighting by the  the result more
                          number of samples in    
                          each class              

  Confusion matrix        Shows actual labels     Helps identify which
                          versus predicted labels classes are confused

  False positive          Normal traffic          Can create unnecessary
                          incorrectly flagged as  investigation work
                          an attack               

  False negative          Attack traffic          Can allow harmful
                          incorrectly classified  activity to go
                          as normal               unnoticed

  ROC-AUC                 Measures how well a     Helps assess
                          binary model separates  ranking/separation
                          classes across          beyond one cutoff
                          thresholds              
  -----------------------------------------------------------------------

### CICIDS2017 multiclass evaluation

The saved CICIDS2017 evaluation summary reports the following results on
**383,203 held-out test samples**:

  Metric                 Saved value   Percentage
  -------------------- ------------- ------------
  Accuracy                `0.998659`     99.8659%
  Macro precision         `0.921818`     92.1818%
  Macro recall            `0.920359`     92.0359%
  Macro F1-score          `0.914891`     91.4891%
  Weighted precision      `0.998810`     99.8810%
  Weighted recall         `0.998659`     99.8659%
  Weighted F1-score       `0.998701`     99.8701%

**How to interpret this:** the overall and weighted metrics are very
high, but macro metrics are lower. This difference is important because
some categories have far fewer examples than `BENIGN`. A model can
perform extremely well on the majority class while still making errors
on rare categories.

Some minority categories in the saved class-wise report have limited
test support. For example, the saved report lists only 5 `Infiltration`
samples, 1 `Heartbleed` sample, and 3 `Web Attack – SQL Injection`
samples. Metrics calculated from such small counts are unstable and
should not be treated as strong evidence of general performance on those
attacks.

### CICIDS2017 threshold-based risk experiment

A separate saved risk-evaluation file reports a binary
attack-versus-benign warning experiment using a threshold of **0.94**:

  Metric                  Saved value   Percentage
  --------------------- ------------- ------------
  Accuracy                 `0.999063`     99.9063%
  Precision                `0.994766`     99.4766%
  Recall                   `0.999640`     99.9640%
  F1-score                 `0.997197`     99.7197%
  False positive rate      `0.001052`      0.1052%
  False negative rate      `0.000360`      0.0360%

The saved confusion counts are **TN = 318,985**, **FP = 336**, **FN =
23**, and **TP = 63,859**.

These figures describe a **separate binary threshold experiment**, not
the 15-class multiclass task. Do not combine them into one result or
compare them as if they measure exactly the same prediction target.

### UNSW-NB15 binary XGBoost experiment

The saved binary baseline report gives:

  Metric        Saved value   Percentage
  ----------- ------------- ------------
  Accuracy       `0.873585`       87.36%
  Precision      `0.822070`       82.21%
  Recall         `0.983213`       98.32%
  F1-score       `0.895450`       89.55%
  ROC-AUC        `0.983548`       98.35%

A saved optimized-model report gives accuracy **87.24%**, precision
**82.15%**, recall **98.16%**, F1-score **89.44%**, and ROC-AUC
**98.33%**. On these saved test metrics, the optimized model did not
improve every metric over the baseline. Hyperparameter tuning should be
judged using the complete evaluation protocol, not the word "optimized"
alone.

### Reading these numbers responsibly

-   The scores apply to the specific saved experiments and test splits.
-   High weighted scores may reflect the influence of large classes.
-   Rare-class metrics can be unstable when only a few examples are
    available.
-   Benchmark results do not establish performance on arbitrary live
    network traffic.
-   The repository has experiment-stage documentation that may contain
    older, inconsistent UNSW-NB15 figures. When reporting results, use
    the relevant saved metric file and record which model and experiment
    produced it.
-   Dashboard metrics should be checked against saved result files
    before being quoted in a report or presentation.

------------------------------------------------------------------------

## 10. Risk scoring and early warning

The CICIDS2017 risk experiment calculates attack probability from the
model's probability of the `BENIGN` class:

``` text
Attack probability = 1 − P(BENIGN)
Risk score         = Attack probability × 100
```

For example, if a compatible model output gives `P(BENIGN) = 0.08`,
then:

``` text
Attack probability = 1 − 0.08 = 0.92
Risk score         = 0.92 × 100 = 92
```

This example is **illustrative only**. It shows the arithmetic, not a
prediction from a real traffic record.

The configured threshold for the saved CICIDS2017 binary risk experiment
is `0.94`. A threshold is a decision cutoff: it controls when a
probability is treated as high enough to raise a warning. Changing the
threshold can change the number of false alarms and missed attacks.

**A risk score is not the same as business impact or attack severity.**
A score of 92 does not mean "92% damage" or prove that an attack is
occurring. It represents the output of the project's chosen formula
under the selected model and data conditions.

------------------------------------------------------------------------

## 11. SHAP explainability

SHAP is a method for estimating how input features contribute to a
model's prediction.

A global SHAP summary can show which features tend to influence
predictions across a collection of records. A local explanation, when
implemented for a particular record, can help show which features pushed
that record's output higher or lower.

Example of how to read an explanation conceptually:

-   A feature may push the model toward an attack-related class.
-   Another feature may push it toward the normal class.
-   The model combines many feature contributions to produce its output.

SHAP explains aspects of **model behavior**. It does not prove that a
feature caused an attack or establish the real-world intent of a
connection.

The repository contains CICIDS2017 SHAP-related files under
`results/cicids2017/Shap/` and an explanation service. Confirm whether a
particular response is a global explanation or a record-specific
explanation before presenting it as such.

------------------------------------------------------------------------

## 12. Application architecture

``` mermaid
flowchart TD
    U[User / Analyst] --> FE[React + TypeScript Dashboard]
    FE --> API[FastAPI Backend]
    API --> INPUT{Input source}
    INPUT --> CSV[Compatible CSV / flow record]
    INPUT --> PCAP[PCAP / PCAPNG upload]
    INPUT --> LIVE[Authorized live interface]
    CSV --> PREP[Validation and dataset-specific preparation]
    PCAP --> PARSE[Scapy packet parsing / flow-like features]
    LIVE --> CAP[Live capture integration]
    PARSE --> PREP
    CAP --> APPROX[Current per-packet feature approximation]
    APPROX --> PREP
    PREP --> CHOOSE{Selected dataset}
    CHOOSE --> C[CICIDS2017 XGBoost pipeline]
    CHOOSE --> N[UNSW-NB15 XGBoost pipelines]
    C --> OUT[Prediction / risk / history services]
    N --> OUT
    OUT --> DB[(SQLite)]
    OUT --> FE
```

### Components in plain language

-   **Frontend:** the website, forms, charts, and dashboard pages.
-   **FastAPI backend:** receives requests, validates inputs, calls the
    prediction code, and returns responses.
-   **Dataset-specific pipelines:** prepare features in the format
    expected by the selected model.
-   **Model artifacts:** saved trained models used for inference.
-   **Risk/explanation services:** provide available risk and
    explanation information.
-   **SQLite:** stores supported application records and history.
-   **Traffic parser and monitoring code:** accept packet-capture files
    and provide a live-monitoring integration path; feature parity still
    needs validation.
-   **Docker Compose and Nginx:** help run the frontend and backend as
    containers.

A **packet** is an individual unit of transmitted network data. A
**flow** summarizes related packets exchanged between endpoints over
time. The benchmark models expect flow-style features, so a reliable
live pipeline needs proper flow aggregation and model-compatible feature
calculations.

------------------------------------------------------------------------

## 13. Current implementation status

This table distinguishes files and code that exist from behavior that
still requires end-to-end validation.

  -----------------------------------------------------------------------
  Area                                Current status
  ----------------------------------- -----------------------------------
  CICIDS2017 multiclass XGBoost       Present
  artifact                            

  UNSW-NB15 binary and multiclass     Present
  XGBoost artifacts                   

  Dataset-specific inference          Present
  pipelines                           

  SQLite persistence and API routes   Present in the application

  React/TypeScript dashboard          Present

  CSV analysis routes and job-service Present; validate with compatible
  integration                         data

  PCAP/PCAPNG parser                  Present; feature equivalence with
                                      benchmark data is not guaranteed

  Live monitoring controls and UI     Present, including a simulated
                                      `test0` mode

  Live traffic feature extraction     Experimental; current live path
                                      uses per-packet approximations
                                      rather than complete bidirectional
                                      flows

  Live attack classification accuracy Not validated; do not treat current
                                      live predictions as operationally
                                      reliable

  CICIDS2017 SHAP artifacts           Present

  Threshold-based risk experiment     Saved evaluation outputs are
                                      present

  Random Forest inference artifact    No Random Forest model artifact was
                                      found in the supplied repository
                                      ZIP

  LSTM temporal model                 Placeholder only; no trained
                                      temporal model artifact configured

  Future-attack forecasting           Not implemented/validated as a
                                      trained temporal prediction
                                      capability

  Dashboard metrics                   Some values may be predefined;
                                      reconcile them against experiment
                                      files before reporting

  Docker setup                        Configuration and Dockerfiles are
                                      present; build and runtime behavior
                                      should be tested in the target
                                      environment
  -----------------------------------------------------------------------

**Important:** The presence of an API route or dashboard screen does not
by itself prove that the complete feature works reliably from input to
output. Test each workflow with known compatible data.

------------------------------------------------------------------------

## 14. Technology stack

  ------------------------------------------------------------------------
  Technology                          Role
  ----------------------------------- ------------------------------------
  Python                              Backend and model integration

  FastAPI                             REST API framework

  Uvicorn                             Runs the FastAPI application

  XGBoost                             Trained tree-based classification
                                      models

  scikit-learn                        ML utilities and
                                      evaluation/preprocessing support

  NumPy and pandas                    Numerical arrays and tabular data

  SQLAlchemy + SQLite                 Database access and local
                                      persistence

  SHAP                                Feature-attribution/explainability
                                      methods and saved outputs

  React                               User interface

  TypeScript                          Typed frontend development

  Vite                                Frontend development server and
                                      build

  Tailwind CSS                        UI styling

  Recharts                            Dashboard charts

  Scapy                               Packet parsing/capture integration

  Docker Compose                      Multi-container development
                                      deployment

  Nginx                               Serves the built frontend and
                                      proxies API requests in the
                                      container setup
  ------------------------------------------------------------------------

------------------------------------------------------------------------

## 15. Repository structure

``` text
.
├── backend/
│   ├── app/
│   │   ├── api/routes/       # Prediction, risk, traffic, monitoring, incidents
│   │   ├── core/             # Configuration and security helpers
│   │   ├── database/         # Database connection, models and repositories
│   │   ├── ml/               # Dataset-specific pipelines and model registry
│   │   ├── models/           # Model-loading and prediction wrappers
│   │   ├── schemas/          # Request and response structures
│   │   ├── services/         # Prediction, parsing, risk, jobs and explanations
│   │   └── main.py           # FastAPI application entry point
│   ├── tests/                # Backend tests
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/            # Dashboard, detection, batch, risk, metrics
│   │   ├── components/       # Reusable UI components
│   │   ├── services/         # API client functions
│   │   └── types/            # TypeScript types
│   └── package.json
├── model-artifacts/
│   ├── cicids2017/           # CICIDS2017 model and label encoder
│   └── unsw-nb15/            # UNSW-NB15 models and label encoder
├── data/                     # Dataset notes and split-index metadata
├── results/                  # Metrics, reports, plots, SHAP and risk outputs
├── docs/                     # Architecture, methodology and API documentation
├── deployment/docker/        # Dockerfiles and Nginx configuration
├── docker-compose.yml
├── requirements.txt
└── README.md
```

### Recommended reading order

1.  This README for the project overview.
2.  `docs/architecture/system-architecture.md` for architecture details.
3.  `docs/methodology/datasets.md` for dataset information.
4.  `docs/methodology/models.md` for model details.
5.  `docs/api/api-documentation.md` for API request and response
    schemas.
6.  `backend/app/services/` for service logic and `frontend/src/pages/`
    for dashboard pages.

------------------------------------------------------------------------

## 16. Run locally

### Prerequisites

-   Python 3.11 recommended.
-   Node.js 20 and npm for the frontend.
-   Git, if cloning the repository.
-   Optional: Docker Desktop or Docker Engine with Docker Compose.
-   For real packet capture: appropriate operating-system permissions
    and authorization to monitor the selected interface.

### Step 1: Get the code

``` bash
git clone <YOUR_REPOSITORY_URL>
cd ML-Based-Cyber-Attack-Analysis-Prediction-and-Early-Warning-System
```

Replace `<YOUR_REPOSITORY_URL>` with the actual repository URL. If the
code is already on your machine, open a terminal at the repository root.

### Step 2: Create a Python environment

**macOS / Linux**

``` bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
```

**Windows PowerShell**

``` powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
```

### Step 3: Start the backend

From the repository root, with the virtual environment activated:

**macOS / Linux**

``` bash
PYTHONPATH=backend uvicorn app.main:app --reload --host 0.0.0.0 --port 8090
```

**Windows PowerShell**

``` powershell
$env:PYTHONPATH = "backend"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8090
```

The backend should be available at:

-   API root: <http://localhost:8090/>
-   Health check: <http://localhost:8090/health>
-   Swagger UI: <http://localhost:8090/docs>
-   ReDoc: <http://localhost:8090/redoc>

Keep the backend terminal running.

### Step 4: Start the frontend

Open a second terminal:

``` bash
cd frontend
npm ci
npm run dev
```

Open <http://localhost:5180> or the URL printed by Vite. The frontend
API client defaults to `http://localhost:8090/api/v1`. If your backend
uses another address, configure `VITE_API_URL` according to the frontend
configuration.

### Step 5: Try a basic workflow

1.  Open the dashboard and inspect model readiness.
2.  Select the single-record prediction or batch-analysis page.
3.  Choose the dataset matching your input.
4.  Submit a complete, compatible record or CSV.
5.  Review the prediction and any available risk information.
6.  Explore history, incidents, metrics, and explanations where
    available.
7.  Use `test0` simulated monitoring to test the monitoring interface
    before trying a real network interface.

------------------------------------------------------------------------

## 17. Run with Docker Compose

From the repository root:

``` bash
docker compose config
docker compose build
docker compose up -d
```

Open:

-   Frontend: <http://localhost:5180>
-   Backend: <http://localhost:8090>
-   Health check: <http://localhost:8090/health>
-   API documentation: <http://localhost:8090/docs>

Useful commands:

``` bash
docker compose ps
docker compose logs -f backend
docker compose logs -f frontend
docker compose down
```

To remove containers **and** the persisted database volume, run the
following only if you intend to delete the stored SQLite data:

``` bash
docker compose down -v
```

The Compose configuration mounts model artifacts read-only and stores
SQLite data in a named volume mounted at `/data`. Confirm that expected
model files exist before starting the backend.

**Live-capture note:** Containerized packet capture may require
additional host permissions, capabilities, and interface visibility.
Test the simulated monitoring mode first. Only configure real capture
deliberately and on authorized systems.

------------------------------------------------------------------------

## 18. Using the application

### Single-record prediction

Use a complete feature record with the schema expected by the selected
dataset. A partial example is shown in the API section, but it is not a
valid complete model input.

### CSV analysis

Use a CSV whose feature columns match the selected dataset pipeline.
CICIDS2017 and UNSW-NB15 schemas are not interchangeable. Missing
columns, unexpected preprocessing, incompatible types, or different
units may cause validation failures or misleading predictions.

### PCAP / PCAPNG analysis

The application contains routes and Scapy-based parsing for supported
packet-capture files. The parser can calculate flow-like statistics, but
it does not guarantee exact reproduction of the original CICIDS2017 or
UNSW-NB15 feature-generation process. Check the job status, number of
processed records, and extracted feature fields.

### Live monitoring

The monitoring UI includes interface selection, start/stop controls,
status, session counters, recent results, and a simulated `test0` mode.

The current live capture path creates approximate feature records from
individual packets rather than maintaining complete bidirectional flows
with benchmark-compatible counts, durations, rates, inter-arrival times,
and other statistics. Live predictions are therefore experimental and
should not be used to claim validated real-world detection accuracy.

Only monitor networks and devices you are authorized to inspect.

------------------------------------------------------------------------

## 19. API overview and examples

Base URL: `http://localhost:8090`

Use <http://localhost:8090/docs> for the exact request and response
schemas exposed by the running application.

  ------------------------------------------------------------------------------------------
  Method                  Endpoint                                   Purpose
  ----------------------- ------------------------------------------ -----------------------
  `GET`                   `/`                                        Basic API information

  `GET`                   `/health`                                  Backend health and
                                                                     model readiness

  `POST`                  `/api/v1/predict`                          Predict a single
                                                                     network-flow record

  `POST`                  `/api/v1/predict/batch`                    Batch prediction,
                                                                     depending on the
                                                                     current route schema

  `POST`                  `/api/v1/analyze`                          Analyze an uploaded
                                                                     traffic CSV

  `POST`                  `/api/v1/traffic/upload`                   Upload CSV, PCAP, or
                                                                     PCAPNG for analysis

  `GET`                   `/api/v1/traffic/jobs`                     List analysis jobs

  `GET`                   `/api/v1/traffic/jobs/{job_id}`            Retrieve job status and
                                                                     summary

  `GET`                   `/api/v1/traffic/jobs/{job_id}/results`    Retrieve analyzed flow
                                                                     results

  `GET`                   `/api/v1/traffic/jobs/{job_id}/download`   Export analysis results

  `GET`                   `/api/v1/traffic/flows`                    Retrieve recent stored
                                                                     flow records

  `GET`                   `/api/v1/monitoring/interfaces`            List permitted capture
                                                                     interfaces

  `GET`                   `/api/v1/monitoring/status`                Check monitoring state
                                                                     and counters

  `POST`                  `/api/v1/monitoring/start`                 Start monitoring

  `POST`                  `/api/v1/monitoring/stop`                  Stop monitoring

  `GET`                   `/api/v1/monitoring/statistics`            Retrieve
                                                                     monitoring-session
                                                                     statistics

  `GET`                   `/api/v1/monitoring/flows`                 Retrieve recent
                                                                     live-monitoring records

  `GET`                   `/api/v1/risk/early-warning`               Retrieve risk/threshold
                                                                     information

  `GET` / `POST`          `/api/v1/explain`                          Retrieve available
                                                                     explanation output

  `GET`                   `/api/v1/metrics`                          Retrieve configured or
                                                                     stored metrics

  `GET`                   `/api/v1/incidents`                        Retrieve incident
                                                                     records, depending on
                                                                     the route schema
  ------------------------------------------------------------------------------------------

### Example single-record request

The following JSON shows the general request shape only. It is **partial
and illustrative**, not a complete valid feature record.

``` json
{
  "dataset": "cicids2017",
  "features": {
    "Destination Port": 80,
    "Flow Duration": 1200,
    "Total Fwd Packets": 5
  }
}
```

The real request must contain all required features with correct names
and values. Do not submit this partial example expecting a valid
prediction.

### Example: test simulated monitoring

Start the built-in simulation:

``` bash
curl -X POST http://localhost:8090/api/v1/monitoring/start \
  -H "Content-Type: application/json" \
  -d '{"interface":"test0","dataset":"cicids2017"}'
```

Check status:

``` bash
curl http://localhost:8090/api/v1/monitoring/status
```

Retrieve recent flows:

``` bash
curl "http://localhost:8090/api/v1/monitoring/flows?limit=10"
```

Stop monitoring:

``` bash
curl -X POST http://localhost:8090/api/v1/monitoring/stop
```

`test0` generates simulated records for development and testing. Those
records do not measure real-world model accuracy.

------------------------------------------------------------------------

## 20. Model artifacts and datasets

The supplied repository includes these main artifacts:

``` text
model-artifacts/
├── cicids2017/
│   ├── CICIDS_Multiclass_XGBoost.json
│   ├── CICIDS_Label_Encoder.npy
│   └── CICIDS_XGBoost_Parameters .json
└── unsw-nb15/
    ├── attack_category_label_encoder.pkl
    ├── xgboost_cyberattack.pkl
    └── xgboost_multiclass_attack_classifier.pkl
```

The CICIDS parameter filename currently contains a space before `.json`.
Check code references before renaming it.

The optional Random Forest path is referenced in the code/history, but a
Random Forest model artifact was not found in the supplied repository
ZIP. The LSTM wrapper is a placeholder and has no trained temporal model
artifact configured.

Raw and large processed datasets are not included. The `data/` directory
contains documentation and split-index metadata. Split indices only
apply to the matching dataset version and row order; they are not a
substitute for the dataset itself.

------------------------------------------------------------------------

## 21. Testing and validation

### Backend tests

From the repository root, with backend dependencies installed:

``` bash
PYTHONPATH=backend pytest backend/tests -v
```

Run the tests in your own environment and review the output. Do not
assume tests pass simply because test files exist.

### Frontend production build

``` bash
cd frontend
npm ci
npm run build
```

### Docker configuration validation

``` bash
docker compose config
```

### Recommended end-to-end checks

1.  Confirm `/health` reports the expected model artifacts as ready.
2.  Submit a complete known-compatible CICIDS2017 record.
3.  Submit a complete known-compatible UNSW-NB15 record.
4.  Upload a small compatible CSV and check processed-row counts.
5.  Upload a small PCAP/PCAPNG file and inspect the extracted fields.
6.  Start `test0` monitoring, confirm the UI updates, and stop the
    session.
7.  Check that history and risk records persist as expected.
8.  Compare packet/flow features with the benchmark dataset's feature
    definitions before evaluating PCAP or live prediction quality.
9.  Run frontend build and Docker checks separately.

------------------------------------------------------------------------

## 22. Troubleshooting

  -----------------------------------------------------------------------
  Problem                             What to check
  ----------------------------------- -----------------------------------
  Model is not ready                  Confirm artifact paths and
                                      filenames; inspect backend logs and
                                      `/health`

  CSV upload fails                    Check dataset selection, required
                                      columns, data types, and feature
                                      schema

  PCAP upload fails                   Check Scapy installation, file
                                      integrity, file size, extension,
                                      and backend logs

  No packets are captured             Check interface name, permissions,
                                      visibility, and interface allowlist

  `test0` shows activity but no real  `test0` is simulated; select a
  network traffic                     permitted real interface for actual
                                      capture

  Live predictions look implausible   Current live feature construction
                                      uses per-packet approximations;
                                      benchmark compatibility is not
                                      validated

  Frontend cannot reach backend       Check port `8090`, `VITE_API_URL`,
                                      and the Nginx `/api` proxy
                                      configuration

  Database errors occur               Check `DATABASE_URL`, SQLite path,
                                      directory permissions, and Docker
                                      volume configuration

  Docker capture does not work        Check host permissions,
                                      capabilities, and whether the
                                      interface is visible inside the
                                      container

  Dashboard metrics differ from       Some dashboard values may be
  result files                        predefined; reconcile with the
                                      saved experiment reports before
                                      quoting them
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 23. Limitations and responsible use

-   This is an academic/research prototype, not a certified commercial
    security product.
-   CICIDS2017 and UNSW-NB15 use separate feature schemas and label
    taxonomies.
-   Model performance depends on training data, preprocessing, class
    balance, feature definitions, and similarity between evaluation data
    and new traffic.
-   High overall accuracy does not guarantee reliable detection of rare
    attacks.
-   False positives and false negatives are possible.
-   PCAP parsing and live feature extraction have not been shown to
    reproduce the benchmark feature-generation process exactly.
-   Live capture currently uses approximate per-packet features; live
    attack classification should be treated as experimental.
-   The LSTM temporal model is not trained/configured, so the
    application should not be described as providing validated
    future-attack forecasting.
-   Risk scores and thresholds are project-specific and are not
    universal security severity ratings.
-   SHAP helps explain model behavior; it does not prove causality.
-   Do not use predictions as the sole basis for blocking traffic or
    taking other high-impact security actions.
-   Only capture traffic from systems and networks you are authorized to
    monitor.
-   Do not commit credentials, private packet captures, personal data,
    or confidential network inventories to a public repository.

------------------------------------------------------------------------

## 24. Future improvements

1.  **Validate and standardize feature extraction:** ensure every input
    field has the correct definition, unit, direction, and
    preprocessing.
2.  **Implement proper live flow aggregation:** group packets into
    bidirectional flows, maintain timeouts, and calculate compatible
    flow statistics.
3.  **Improve input validation:** reject missing or incompatible fields
    instead of silently filling them with invented values.
4.  **Reconcile evaluation sources:** map every reported metric to the
    exact model artifact, script, test split, and experiment.
5.  **Use one source of truth for dashboard metrics:** load documented
    results rather than maintaining inconsistent hard-coded values.
6.  **Expand class-wise evaluation:** track precision, recall, F1,
    support, confusion matrices, false positives, and false negatives
    for each label.
7.  **Validate PCAP workflows:** compare extracted fields with reference
    features from the original dataset-generation method.
8.  **Strengthen application security:** add appropriate authentication,
    upload limits, retention rules, and operational logging before any
    real deployment.
9.  **Explore temporal early warning as a separate research stage:** use
    timestamped chronological data, define a future-event target, train
    a sequence model only when justified, and evaluate warning lead time
    and false alarms.
10. **Test deployment reproducibly:** run backend tests, frontend build,
    Docker build, and clean database initialization in a documented
    environment.

------------------------------------------------------------------------

## 25. Beginner glossary

  -----------------------------------------------------------------------
  Term                                Meaning
  ----------------------------------- -----------------------------------
  **Cyberattack**                     An attempt to disrupt, misuse, or
                                      gain unauthorized access to a
                                      computer system or network

  **Network packet**                  A unit of data sent across a
                                      network

  **Network flow**                    A summary of related communication
                                      between endpoints over time

  **Dataset**                         A collection of examples used for
                                      training or evaluation

  **Feature**                         One measurable input value, such as
                                      packet count or flow duration

  **Label / class**                   The category assigned to a record,
                                      such as `BENIGN`, `DDoS`, or
                                      `PortScan`

  **Training**                        The process of learning patterns
                                      from labelled examples

  **Inference**                       Using a trained model to make a
                                      prediction on input data

  **XGBoost**                         A machine-learning method that
                                      combines decision trees

  **Binary classification**           Choosing between two classes, such
                                      as normal and attack

  **Multiclass classification**       Choosing one class from a list of
                                      several labels

  **Probability**                     A model's estimated likelihood for
                                      a class under its learned patterns

  **Threshold**                       A cutoff used to turn a probability
                                      into a warning decision

  **Risk score**                      A project-defined numeric summary
                                      derived from model output

  **False positive**                  Normal activity incorrectly flagged
                                      as suspicious

  **False negative**                  Attack activity incorrectly
                                      classified as normal

  **Macro average**                   An average that gives each class
                                      equal weight

  **Weighted average**                An average where classes with more
                                      samples have more influence

  **Confusion matrix**                A table showing correct predictions
                                      and class-to-class errors

  **SHAP**                            A method for estimating how
                                      features contributed to model
                                      output

  **PCAP / PCAPNG**                   File formats for storing captured
                                      network packets

  **API**                             A defined way for software
                                      components to communicate

  **Backend**                         The part of an application that
                                      processes requests and runs logic

  **Frontend**                        The website or dashboard a user
                                      interacts with

  **SQLite**                          A lightweight database stored in a
                                      file

  **Docker**                          A tool for packaging applications
                                      and dependencies into containers

  **Early warning**                   A warning generated by a defined
                                      rule or model output; future-event
                                      forecasting needs a separate
                                      validated temporal approach
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## License

See [`LICENSE`](LICENSE) for the license included with this repository.
Confirm that it matches the terms under which you intend to distribute
the project and its artifacts.

## Acknowledgements

This project uses ideas, datasets, and open-source software from the
cybersecurity and machine-learning communities, including CICIDS2017,
UNSW-NB15, FastAPI, React, XGBoost, SQLite, SHAP-related tooling, Scapy,
and Docker. Refer to the original dataset providers and software
licenses for their terms of use.
