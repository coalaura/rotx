package config

func compileHeaderPlans(parent []headerPlan, operations []headerOperation) []headerPlan {
	if len(operations) == 0 {
		return parent
	}

	plans := make([]headerPlan, len(parent), len(parent)+len(operations))

	copy(plans, parent)

	indexes := make(map[string]int, len(parent)+len(operations))

	for index := range plans {
		indexes[plans[index].name] = index
	}

	for index := range operations {
		operation := &operations[index]

		position, exists := indexes[operation.name]
		if !exists {
			position = len(plans)

			indexes[operation.name] = position

			plans = append(plans, headerPlan{name: operation.name, append: true})
		}

		plan := &plans[position]

		switch operation.kind {
		case "header_unset":
			plan.values = nil
			plan.append = false
		case "header_set":
			plan.values = []string{operation.value}
			plan.append = false
		case "header_add":
			values := make([]string, len(plan.values)+1)

			copy(values, plan.values)

			values[len(plan.values)] = operation.value

			plan.values = values
		}
	}

	return plans
}
