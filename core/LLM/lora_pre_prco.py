import train_const as my_c
import torch
from transformers import    BitsAndBytesConfig


def get_bnb_config():
    compute_dtype = getattr(torch, my_c.bnb_4bit_compute_dtype)
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=my_c.use_4bit,
        bnb_4bit_quant_type=my_c.bnb_4bit_quant_type,
        bnb_4bit_compute_dtype=compute_dtype,
        bnb_4bit_use_double_quant=my_c.use_nested_quant,
    )

    # Check GPU compatibility with bfloat16
    if compute_dtype == torch.float16 and my_c.use_4bit:
        major, _ = torch.cuda.get_device_capability()
        if major >= 8:
            print("=" * 80)
            print("Your GPU supports bfloat16: accelerate training with bf16=True")
            print("=" * 80)
    return bnb_config