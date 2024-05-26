

class TrainConst:
    def __init__(self):
        # peft target module
        self.target_modules=["q_proj", "v_proj"]

        self.lora_r = 64

        # Alpha parameter for LoRA scaling
        self.lora_alpha = 16

        # Dropout probability for LoRA layers
        self.lora_dropout = 0.1

        # Enable fp16/bf16 training (set bf16 to True with an A100)
        self.fp16 = True
        self.bf16 = False

        # Enable gradient checkpointing
        self.gradient_checkpointing = True

        # Maximum gradient normal (gradient clipping)
        self.max_grad_norm = 0.3

        # Weight decay to apply to all layers except bias/LayerNorm weights
        self.weight_decay = 0.001

        # Optimizer to use
        self.optim = "paged_adamw_32bit"

        # Group sequences into batches with same length
        # Saves memory and speeds up training considerably
        self.group_by_length = True

        # Log every X updates steps
        self.logging_steps = 5

        # evaluate model after n steps
        self.eval_steps = 50

        ################################################################################
        # SFT parameters
        ################################################################################

        # Maximum sequence length to use
        self.max_seq_length = 1024

        # Pack multiple short examples in the same input sequence to increase efficiency
        self.packing = False

        # Load the entire model on the GPU 0
        self.device_map = "auto"


############################################
# for codellama 7b
############################################
class Codellama_7b_TrainConst(TrainConst):
    def __init__(self):
        super().__init__()
        # Batch size per GPU for training

        self.per_device_train_batch_size = 8
        # Batch size per GPU for evaluation
        self.per_device_eval_batch_size = 16

        # Number of update steps to accumulate the gradients for
        self.gradient_accumulation_steps = 8

        # Save checkpoint every X updates steps
        self.save_steps = 50

        # Number of training steps (overrides num_train_epochs)
        self.max_steps = 400

        # steps for a linear warmup (from 0 to learning rate)
        self.warmup_steps = 50

        # Initial learning rate (AdamW optimizer)
        self.learning_rate = 2e-4

        # Number of training epochs
        self.num_train_epochs = 3

        # set padding token as eos
        self.set_eos = True

############################################
# for code t5+ 770m
############################################
class Codet5p_770m_TrainConst(TrainConst):
    def __init__(self):
        # Batch size per GPU for training
        super().__init__()
        self.per_device_train_batch_size = 16
        # Batch size per GPU for evaluation
        self.per_device_eval_batch_size = 48

        #target_modules
        self.target_modules = ['q', 'v']

        # Number of update steps to accumulate the gradients for
        self.gradient_accumulation_steps = 8

        # Save checkpoint every X updates steps
        self.save_steps = 25

        # Number of training steps (overrides num_train_epochs)
        self.max_steps = 300

        # steps for a linear warmup (from 0 to learning rate)
        self.warmup_steps = 50

        # Initial learning rate (AdamW optimizer)
        self.learning_rate = 1e-3

        # Number of training epochs
        self.num_train_epochs = 3

        # set padding token as eos
        self.set_eos = False


############################################
# for starcoder2 7b
############################################
class Starcoder2_7b_TrainConst(TrainConst):
    def __init__(self):
        # Batch size per GPU for training
        super().__init__()
        self.per_device_train_batch_size = 8
        # Batch size per GPU for evaluation
        self.per_device_eval_batch_size = 16

        # Number of update steps to accumulate the gradients for
        self.gradient_accumulation_steps = 8

        # Save checkpoint every X updates steps
        self.save_steps = 50

        # Number of training steps (overrides num_train_epochs)
        self.max_steps = 300

        # steps for a linear warmup (from 0 to learning rate)
        self.warmup_steps = 25

        # Initial learning rate (AdamW optimizer)
        self.learning_rate = 8e-4

        # Number of training epochs
        self.num_train_epochs = 3

        # set padding token as eos
        self.set_eos = True

############################################
# for starcoder2 3b
############################################
class Starcoder2_3b_TrainConst(TrainConst):
    def __init__(self):
        # Batch size per GPU for training
        super().__init__()
        self.per_device_train_batch_size = 16
        # Batch size per GPU for evaluation
        self.per_device_eval_batch_size = 32

        # Number of update steps to accumulate the gradients for
        self.gradient_accumulation_steps = 8

        # Save checkpoint every X updates steps
        self.save_steps = 50

        # Number of training steps (overrides num_train_epochs)
        self.max_steps = 300

        # steps for a linear warmup (from 0 to learning rate)
        self.warmup_steps = 25

        # Initial learning rate (AdamW optimizer)
        self.learning_rate = 8e-4

        # Number of training epochs
        self.num_train_epochs = 3

        # set padding token as eos
        self.set_eos = True

############################################
# for code t5+ 2b
############################################
class Codet5p_2b_TrainConst(TrainConst):
    def __init__(self):
        # Batch size per GPU for training
        super().__init__()
        self.per_device_train_batch_size = 16
        # Batch size per GPU for evaluation
        self.per_device_eval_batch_size = 32

        # Number of update steps to accumulate the gradients for
        self.gradient_accumulation_steps = 8

        # Save checkpoint every X updates steps
        self.save_steps = 50

        # Number of training steps (overrides num_train_epochs)
        self.max_steps = 300

        # steps for a linear warmup (from 0 to learning rate)
        self.warmup_steps = 25

        # Initial learning rate (AdamW optimizer)
        self.learning_rate = 4e-3

        # Number of training epochs
        self.num_train_epochs = 3

        # set padding token as eos
        self.set_eos = False