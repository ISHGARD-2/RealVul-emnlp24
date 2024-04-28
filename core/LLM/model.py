from torch import nn, optim


class CodeT5PClassifier(nn.Module):
    def __init__(self, input_size, hidden_size, output_size, model):
        super(CodeT5PClassifier, self).__init__()
        self.fc1 = nn.Linear(input_size, hidden_size)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(hidden_size, output_size)
        self.sigmoid = nn.Sigmoid()
        self.model = model
        for param in self.model.parameters():
            param.requires_grad = False

    def forward(self, x):
        input_ids =x
        x = self.model(input_ids = input_ids)
        x = x.last_hidden_state[:,0,:].squeeze()
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        x = self.sigmoid(x)
        return x.squeeze()