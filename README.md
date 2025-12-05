# Google Cloud DFIR

This repository contains tools, scripts, and reference material to support **Digital Forensics & Incident Response (DFIR)** on **Google Cloud (GCP)**.

The primary focus is on **log acquisition** to support investigations, threat hunting, and compliance activities.

---

## Log Collection Options

This repository currently provides two main approaches for downloading logs from Google Cloud:

1. **Google Cloud Log Download via Google Cloud CLI (`gcloud`)**  
   Step-by-step instructions for exporting Cloud Logging data using the `gcloud` command-line interface.

   👉 [Google Cloud Log Download via Google Cloud CLI](./CLI%20Log%20Collection/README.md)

2. **Google Cloud Log Download via API (Python script)**  
   A Python-based collector that uses the Cloud Logging API and OAuth, designed for incident response workflows.  
   Includes options for project and bucket selection, time-scoping, filtering, and output control.

   👉 [Google Cloud Log Download via API (Python)](./API%20Log%20Collection/README.md)

> **Note:** Folder names and paths may be adjusted as the repository evolves. If a link is broken, check the directory tree for the latest locations.

---

## Repository Overview

This repository is intended as a **collection of DFIR utilities** for Google Cloud, for use by:

- Incident responders
- Threat hunters
- Security operations teams
- Trainers and educators working with Google Cloud DFIR material

As new tools and approaches are developed, they will be added here with their own dedicated documentation.

---

## Items Under Development

The following items are currently planned or in progress:

- **Dockerised version of the API Log Collector**
  - Container image for running the Python-based log collector without requiring a local Python environment.
  - Support for mounting credentials and output directories to simplify usage in labs, training, and automation pipelines.
  - Once available, usage instructions and example `docker run` commands will be added to the API Log Collection README and linked from this file.

Additional DFIR utilities and workflows for Google Cloud may be added over time.

---

## Release Notes / Revision History

- **v0.1.0** – Initial repository overview and entry-point README:
  - Added top-level documentation.
  - Linked to:
    - Google Cloud CLI log download instructions.
    - API (Python) log download instructions.
  - Documented “Items Under Development” and attribution/disclaimer sections.

---

## Attribution & Credits

This repository, including the log download tooling and documentation, has been created and curated by:

**Josh Lemon** from **SoteriaSec**

If you reference this work, please credit:

> *“Log collection and DFIR tooling for Google Cloud developed by Josh Lemon (SoteriaSec).”*

---

## Usage, Training & Commercial Content Disclaimer

Use of the scripts, documentation, and examples in this repository is at your own risk. They are provided **“as-is”** without any warranty or guarantee of fitness for a particular purpose. Always validate tooling in a test environment before using it in production or on live incident data.

If you:

- Include these scripts or documentation in **training material**,  
- Use them as part of **commercial content**, courses, or workshops, or  
- Distribute modified versions as part of your own offerings,

you must:

1. **Clearly attribute** the original work to:

   > *“Original Google Cloud DFIR log collection tooling by Josh Lemon (SoteriaSec).”*

2. **Not remove or obscure** existing references to Josh Lemon or SoteriaSec in the scripts or documentation.

3. Ensure any modifications or extensions are not misrepresented as the original work.

For questions about usage, attribution, or collaboration, please reach out via SoteriaSec.
