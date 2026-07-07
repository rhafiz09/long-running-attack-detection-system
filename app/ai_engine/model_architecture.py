import logging
import keras
from keras import layers
from keras.models import Sequential

logger = logging.getLogger(__name__)


def create_cnn_lstm_model(input_shape: tuple, num_classes: int = 4) -> keras.Model:
    """
    Defines and compiles a hybrid CNN-LSTM Keras model for 4-class cybersecurity log classification.
    
    Architecture:
    1. Input Layer: (timesteps, features)
    2. Conv1D: Extracts local spatial relations / features across sequential behavior windows.
    3. MaxPooling1D: Downsamples spatial dimensions.
    4. LSTM: Captures long-running temporal patterns across multiple sequence steps.
    5. Dense Classifier: Dense and Dropout layers culminating in a softmax activation.
    """
    logger.info(f"Building hybrid CNN-LSTM Model with input_shape={input_shape}, num_classes={num_classes}...")

    # Validate pool size against input timesteps
    timesteps, features = input_shape
    pool_size = 2
    if timesteps < 3:
        # Prevent downsampling errors for very short sequence definitions
        pool_size = 1

    model = Sequential([
        layers.Input(shape=input_shape),
        
        # 1. Spatial convolutional layers
        layers.Conv1D(
            filters=64,
            kernel_size=3,
            activation="relu",
            padding="same",
            name="spatial_conv1d"
        ),
        layers.MaxPooling1D(
            pool_size=pool_size,
            name="spatial_maxpool"
        ),
        
        # 2. Temporal sequence layers
        layers.LSTM(
            units=64,
            return_sequences=False,
            dropout=0.2,
            name="temporal_lstm"
        ),
        
        # 3. Dense Classifier layer
        layers.Dense(
            units=32,
            activation="relu",
            name="dense_feature"
        ),
        layers.Dropout(
            0.3,
            name="dropout_regularization"
        ),
        
        # 4. Softmax activation for multi-class classification
        layers.Dense(
            units=num_classes,
            activation="softmax",
            name="softmax_output"
        )
    ])

    # 5. Compile model with enterprise metrics
    model.compile(
        optimizer="adam",
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )

    logger.info("CNN-LSTM Model compiled successfully.")
    model.summary(print_fn=lambda x: logger.debug(x))
    return model
