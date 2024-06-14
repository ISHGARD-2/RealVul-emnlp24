# RealVul: PHP Vulnerability Detection based on LLMs

## Overview
This repository contains the code for our prototype implementation of RealVul. RealVul is a LLM-based framework signed for PHP vulnerability detection on CWE-79 (XSS) and CWE-89 (SQL Injection). 


## Getting Started

### Environment Setup
install the python dependencies via the following command:

```
pip install -r requirements.txt
```

### Pre-trained LLM Download

#### Code LLM Models
We use 5 different Code LLMs as base model for fine-tuning. In this repository, we use CodeLlama-7B model as an example to reproduce the main results from the paper. This is how to obtain this pre-trained model:

   - Make sure you have git-lfs installed. If not, run the command: 
   ```
git lfs install
```
   - Execute the command to download the model:
   ```
git clone https://huggingface.co/meta-llama/CodeLlama-7b-hf
``` 


#### Datasets
To download the training and evaluation dataset used for evaluation in our experiments, run the following commands:

```
cd data 
gdown https://drive.google.com/file/d/1-PKETn0EvTkTrJCF4ZkcOHkviIUi6aLo/
```

## Pipeline

### Sampling to generate code snippets as samples:
```
main.py 
    --task Sampling
    --cwe 79
    --sampling_target_dir ./data/crossvul/xss/
    --sampling_output_dir ./result/snippet/
```

### Preprocessing with labeled samples:
```
main.py 
    --task Preprocessing
    --cwe 79
    --prep_target_file ./result/CVI_10001_dataset.json
    --prep_output_file ./result/dataset_unique_79.json
```


### Data Synthesis:
```
main.py 
    --task Synthesis
    --cwe 79
    --sard_samples_file ./data/SARD_php_vulnerability_79.json
    --crossvul_samples_file ./data/dataset_unique_79.json
    --synthesis_target_dir ./data/crossvul/xss/
```

## Start Fine-tuning

### Train:
For train mode, we support:
 - random: Fine-tune RealVul on random Samples.
 - unseen: Fine-tune RealVul on unseen projects.
 - random_without_slice: Fine-tune Baseline on random Samples.
 - unseen_without_slice: Fine-tune Baseline on unseen projects.
 - random_without_preprocess: Ablation Study on Normalization.
 - unseen_without_preprocess: Ablation Study on Normalization.
```
main.py 
    --task Training
    --cwe 79
    --crossvul_dataset ./data/dataset_unique_79.json
    --synthesis_dataset ./data/dataset_synthesis_79.json
    --train_mode random
    --base_model codellama-7b
    --base_model_dir ./models/base_model/codellama-7b/
```

### Eval:

```
main.py 
    --task Evaluation
    --cwe 79
    --crossvul_dataset ./data/dataset_unique_79.json
    --synthesis_dataset ./data/dataset_synthesis_79.json
    --train_mode random
    --base_model codellama-7b
    --base_model_dir ./models/base_model/codellama-7b/
```
```
