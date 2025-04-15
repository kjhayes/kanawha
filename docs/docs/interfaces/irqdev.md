
Kanawha IRQ Device Interface
============================

## IRQ Device Methods

Every IRQ device driver must implement the following functions

### irq_dev_mask_irq
```C
int irq_dev_mask(struct irq_dev *dev, hwirq_t hwirq);
```

Masks the specified `hwirq` making it so the IRQ is not able to be delivered.

Returns 0 on success or negative `errno` on failure.

### irq_dev_unmask_irq
```C
int irq_dev_unmask(struct irq_dev *dev, hwirq_t hwirq);
```

Un-masks the specified `hwirq` allowing it to be delivered.

Returns 0 on success or negative `errno` on failure.

### irq_dev_irq_status
```C
unsigned long irq_dev_irq_status(struct irq_dev *dev, hwirq_t hwirq);
```

Returns the current status of the `hwirq` using the bit-wise or of the following macros
- `IRQ_STATUS_INVALID` : An error occurred reading the status.
- `IRQ_STATUS_UNKNOWN` : The status is currently unknown (ignore the following fields).
- `IRQ_STATUS_MASKED` : The IRQ is masked.
- `IRQ_STATUS_PENDING` : The IRQ is pending.

The value returned by this function should not be relied upon by the kernel,
and should only be used for debugging print-outs.

### irq_dev_ack_irq

```C
int irq_dev_ack_irq(struct irq_dev *dev, hwirq_t to_ack);
```

Called by generic IRQ handling functions when an interrupt specified by `to_ack` arrives.

Returns 0 on success, negative `errno` on error.

### irq_dev_eoi_irq
```C
int irq_dev_eoi_irq(struct irq_dev *dev, hwirq_t to_eoi);
```

Called by generic IRQ handling functions at the end of handling the interrupt specified by `to_eoi`.

Returns 0 on success, negative `errno` on error.

### irq_dev_trigger_irq

```C
int irq_dev_trigger_irq(struct irq_dev *dev, hwirq_t hwirq);
```

"Triggers" the specified `hwirq` this could simply mean running the associated descriptor's handlers. Or it could require sending an IPI if the hwirq is associated with a different core.

Returns 0 on success or a negative `errno` on failure.

### irq_dev_describe_irq
```C
int
irq_dev_describe_irq(struct irq_dev *dev, hwirq_t irq, char *buffer, size_t buflen);
```

Writes a string providing a more "descriptive" name of the specified `irq` into `buffer` which is of length `buflen`.

Returns 0 on success or negative `errno` on failure.

