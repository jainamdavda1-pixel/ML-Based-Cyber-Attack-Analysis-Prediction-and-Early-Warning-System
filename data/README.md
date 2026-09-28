# Dataset Storage & Access Policy

> **Important Note**: Raw and large processed datasets for **UNSW-NB15** and **CICIDS2017** are not stored in this GitHub repository to avoid large file tracking issues and keep the repository clean.

## Dataset Storage Location
All datasets are maintained separately in external shared storage:
- **Google Drive / External Storage**: Please refer to project documentation for the access link.

## Repository Contents
This directory contains only reproducible metadata and split indices:
- `data/unsw-nb15/splits/`: Train, test, and validation indices for UNSW-NB15.
- `data/cicids2017/splits/`: Train, test, and validation indices for CICIDS2017 (`train_indices.npy`, `test_indices.npy`, `validation_indices.npy`).

## Dataset Separation
The project maintains **UNSW-NB15** and **CICIDS2017** as independent datasets with separate feature sets and attack taxonomies. They are processed and evaluated independently.
