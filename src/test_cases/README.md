# Test Cases

This folder holds the example scenarios used to exercise the pipeline end to end. Each scenario is a self-contained network description that flows through environment correlation, MulVAL attack graph generation, and post-processing.

Select a scenario at run time:

```sh
make run SCENARIO=scenario1
make run SCENARIO=scenario2
make run SCENARIO=scenario3
```

## Scenarios

- `scenario1/`: three victim machines exposed to internet-delivered client-side attacks
- `scenario2/`: e-commerce application (Magento) multi-tier deployment
- `scenario3/`: enterprise healthcare patient portal (HIS) multi-tier deployment

## Layout

Each scenario follows the same structure:

- `enviroment/`: scenario inputs and the generated `scenario.P` MulVAL input
- `gen_graph/`: attack graph outputs produced by MulVAL
- `post_processing/`: risk reports and annotated graphs created after generation

See each scenario's README for details.
