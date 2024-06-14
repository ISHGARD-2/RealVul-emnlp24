import sys

import logging

from accelerate import Accelerator
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import (
    TrainingArguments,
    DataCollatorWithPadding, T5ForSequenceClassification
)
from trl import SFTTrainer
from peft import LoraConfig, TaskType, PeftModel

from configs.settings import LLM_ENV_PATH, DATA_PATH, MODEL_PATH
from core.LLM.dataset import get_crossvul_data
import torch

from utils.log import logger, log


class MyTrainer(SFTTrainer):

    def compute_loss(self, model, inputs, return_outputs=False):
        """
        How the loss is computed by Trainer. By default, all models return the loss in the first element.
        Subclass and override for custom behavior.
        """


        outputs = model(**inputs)
        labels = inputs['labels']

        # code for calculating accuracy
        # preds = outputs.logits.detach().argmax(axis=1).tolist()
        # acc1 = accuracy_score(labels.tolist(), preds)
        # self.log({'accuracy_score': acc1})
        # end code for calculating accuracy

        logits = outputs.logits
        loss_fn = torch.nn.CrossEntropyLoss()
        loss = loss_fn(logits, labels)
        return (loss, outputs) if return_outputs else loss


def train_model(base_model_path, load_class, train_const, train_task, train_dataset, eval_dataset, tokenizer, output_model_path, new_model_path,
                check_point_path=''):
    """

    """
    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    model = load_class.from_pretrained(
        base_model_path,
        num_labels=2,
        device_map=train_const.device_map,
        output_scores=True
    )

    # Load LoRA configuration
    peft_config = LoraConfig(
        lora_alpha=train_const.lora_alpha,
        lora_dropout=train_const.lora_dropout,
        r=train_const.lora_r,
        bias="none",
        task_type=train_const.train_task[train_task],
        target_modules=train_const.target_modules
    )

    # Set training parameters
    training_arguments = TrainingArguments(
        output_dir=output_model_path,
        per_device_train_batch_size=train_const.per_device_train_batch_size,
        gradient_accumulation_steps=train_const.gradient_accumulation_steps,
        optim=train_const.optim,
        save_steps=train_const.save_steps,
        logging_steps=train_const.logging_steps,
        learning_rate=train_const.learning_rate,
        weight_decay=train_const.weight_decay,
        fp16=train_const.fp16,
        max_grad_norm=train_const.max_grad_norm,
        num_train_epochs=train_const.num_train_epochs,
        # max_steps=train_const.max_steps,
        warmup_steps=train_const.warmup_steps,
        group_by_length=train_const.group_by_length,
        report_to="none",
        eval_steps=train_const.eval_steps,
        evaluation_strategy="steps"
    )
    logger.info(new_model_path)

    if train_const.set_eos:
        model.config.pad_token_id = model.config.eos_token_id
    model.config.use_cache = False

    trainer = MyTrainer(
        model=model,
        args=training_arguments,
        max_seq_length=train_const.max_seq_length,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        dataset_text_field="text",
        peft_config=peft_config,
        data_collator=data_collator,
        # compute_metrics=compute_metrics
    )

    if torch.__version__ >= "2" and sys.platform != "win32":
        logger.info("compiling the model")
        torch.compile(model)

    # Train model
    logger.info("[LLM] Go training")

    if check_point_path != '':
        trainer.train(resume_from_checkpoint=True)
    else:
        trainer.train()

    trainer.save_model(new_model_path)
    if 'T5ForSequenceClassification' == load_class.__name__:
        torch.save(model.state_dict(), new_model_path+'.pt')
    logger.info("[LLM] Training is over")
