# https://zhuanlan.zhihu.com/p/660933421
import time
import datetime
import os
import sys
import logging
import torch
import json
from peft import (
    LoraConfig,
    get_peft_model,
    get_peft_model_state_dict,
    prepare_model_for_int8_training,
    set_peft_model_state_dict,
    PeftModel
)
from transformers import AutoTokenizer, AutoModelForCausalLM, TrainingArguments, Trainer, DataCollatorForSeq2Seq, GenerationConfig, LlamaForSequenceClassification
from datasets import load_dataset
from accelerate import Accelerator
from dataset import TextDataset
from tqdm import tqdm

os.environ["WANDB_DISABLED"] = "true"
os.environ["TOKENIZERS_PARALLELISM"] = "true"

logger = logging.getLogger(__name__)

# CUDA_VISIBLE_DEVICES=0,1,2,3
MAX_INPUT_LEN = 1024
ENV_PATH = "/home/dcao/code/Python/LLM/CodeLlama/codellama-instruct-13b/"

def train(train_path, test_path, output_dir, base_model):
    batch_size = 64
    per_device_train_batch_size = 8
    gradient_accumulation_steps = batch_size // per_device_train_batch_size
    warmup_steps = 100
    max_steps = 1200
    eval_steps = 400
    save_steps = 400

    # AutoModelForCausalLM
    model = LlamaForSequenceClassification.from_pretrained(
        base_model,
        load_in_8bit=False,
        torch_dtype=torch.float16,
        device_map="auto",
    )

    # if checkpoint_dir:
    #     if os.path.exists(checkpoint_dir):
    #         print(f"Restarting from {checkpoint_dir}")
    #         adapters_weights = torch.load(checkpoint_dir)
    #         set_peft_model_state_dict(model, adapters_weights)
    #     else:
    #         print(f"Checkpoint {checkpoint_dir} not found")


    tokenizer = AutoTokenizer.from_pretrained(base_model)
    tokenizer.add_eos_token = True
    tokenizer.pad_token_id = 0
    tokenizer.padding_side = "left"
    model.config.pad_token_id = model.config.eos_token_id

    tokenized_train_dataset = TextDataset(train_path, tokenizer)
    tokenized_test_dataset = TextDataset(test_path, tokenizer)

    logger.info("length of train data: {}".format(tokenized_train_dataset))
    logger.info("length of test data: {}".format(tokenized_test_dataset))

    model.train()  # put model back into training mode
    model = prepare_model_for_int8_training(model)
    config = LoraConfig(
        r=16,
        lora_alpha=16,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
        ],
        lora_dropout=0.01,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, config)

    if torch.cuda.device_count() > 1:
        # keeps Trainer from trying its own DataParallelism when more than 1 gpu is available
        model.is_parallelizable = True
        model.model_parallel = True

    training_args = TrainingArguments(
        # dataloader_num_workers=8,
        per_device_train_batch_size=per_device_train_batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        #train_batch_size = train_batch_size,
        warmup_steps=warmup_steps,
        max_steps=max_steps,
        learning_rate=2e-4,
        fp16=True,
        logging_steps=20,
        optim="adamw_torch",
        evaluation_strategy="steps",  # if val_set_size > 0 else "no",
        save_strategy="steps",
        eval_steps=eval_steps,
        save_steps=save_steps,
        output_dir=output_dir,
        load_best_model_at_end=False,
        group_by_length=True,  # group sequences of roughly the same length together to speed up training
        report_to="none",  # if use_wandb else "none",
        run_name=f"codellama-{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M')}",  # if use_wandb else None,
    )

    trainer = Trainer(
        model=model,
        train_dataset=tokenized_train_dataset,
        eval_dataset=tokenized_test_dataset,
        args=training_args,
        data_collator=DataCollatorForSeq2Seq(
            tokenizer, return_tensors="pt", padding=True
        ),
    )

    model.config.use_cache = False
    old_state_dict = model.state_dict
    model.state_dict = (lambda self, *_, **__: get_peft_model_state_dict(self, old_state_dict())).__get__(
        model, type(model)
    )

    if torch.__version__ >= "2" and sys.platform != "win32":
        logger.info("compiling the model")
        model = torch.compile(model)

    logger.info("training the model")
    # DataCollatorForSeq2Seq.pad_to_multiple_of = None
    trainer.train()

def eval(eval_path, checkpoint_dir, base_model, train_type="supervised"):
    if train_type == "supervised":
        model = LlamaForSequenceClassification.from_pretrained(
            base_model,
            load_in_8bit=True,
            torch_dtype=torch.float16,
            device_map="auto",
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            base_model,
            load_in_8bit=True,
            torch_dtype=torch.float16,
            device_map="auto",
        )
    model = PeftModel.from_pretrained(model, checkpoint_dir)

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    tokenized_eval_dataset = TextDataset(eval_path, tokenizer, "eval", train_type)

    evalmatrix = [0, 0, 0, 0, 0]  # 00,01,10,11,error of label/outp

    with torch.no_grad():
        for eval_prompt, label in tqdm(zip(tokenized_eval_dataset.tokens, tokenized_eval_dataset.label)):
            label = label["labels"]
            label_num = 1 if label == 'vulnerable' else 0
            label_num = torch.tensor([label_num])

            model_input = tokenizer(eval_prompt, return_tensors="pt", max_length=MAX_INPUT_LEN, truncation=True,
                                    padding=False).to("cuda")

            model.eval()

            generation_config = GenerationConfig(
                do_sample=True,
                top_p=0.95,
                top_k=10,
                num_beams=1,
                eos_token_id=tokenizer.eos_token_id,
                pad_token_id=tokenizer.pad_token_id,
                max_new_tokens=4,
            )

            if train_type == "supervised":
                out = model(input_ids=model_input["input_ids"], labels=label_num)
                logits = out.logits.cpu().numpy()
                logit_0 = logits[0][0]
                logit_1 = logits[0][1]

                pred = '-1'
                if logit_1 >= logit_0:
                    pred = '1'
                else:
                    pred = '0'

                logger.info("\nlogit_0: {0} ; logit_1 : {1}".format(logit_0, logit_1))

            elif train_type == "self-supervised":
                #logger.info("4:"+ torch.cuda.max_memory_allocated() / 1024 ** 2)
                s = model.generate(**model_input, generation_config=generation_config)

                #logger.info("4.5:"+ torch.cuda.max_memory_allocated() / 1024 ** 2)
                out = str(tokenizer.decode(s[0], skip_special_tokens=True))

                assert "### Response:" in out, out
                outp = out[out.index("### Response:"):].lower()

                pred = '-1'
                if 'vul' in outp:
                    pred = '1'
                elif 'secure' in outp:
                    pred = '0'
                elif 'insecure' in outp:
                    pred = '1'

                logger.info('label: {label}\noutput seq: {seq}\n'.format(label=label, seq=outp.replace('\n', '')))

            if label == 'secure' and pred == '0':
                evalmatrix[0] += 1
            elif label == 'secure' and pred == '1':
                evalmatrix[1] += 1
            elif label == 'vulnerable' and pred == '0':
                evalmatrix[2] += 1
            elif label == 'vulnerable' and pred == '1':
                evalmatrix[3] += 1
            else:
                evalmatrix[4] += 1
            logger.info('evalmatrix: {}'.format(evalmatrix))


if __name__ == '__main__':

    output_dir = 'vul-code-llama/codellama-7b-ins_' + str(datetime.date.today())
    output_dir = 'vul-code-llama/codellama-7b-ins_2023-11-23'
    base_model = ENV_PATH+"/models/7b"
    dataset_path = ENV_PATH+"/dataset/devign_test.json"
    # test_dataset_path = ENV_PATH+"/dataset/devign_test.json"

    #train("devign.json_train.json", "devign.json_test.json", output_dir, base_model)

    output_dir += '/checkpoint-400'

    eval("devign.json_eval.json", output_dir, base_model, train_type="self-supervised")