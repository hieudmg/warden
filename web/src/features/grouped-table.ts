export interface GroupedTableItem {
  id: number
  name: string
  group_id: number
  group_name?: string
}

export interface GroupedTableRow<T extends GroupedTableItem> {
  item: T
  groupLabel: string
  backgroundClass: string
}

const groupBackgroundClasses = [
  "bg-red-100",
  "bg-orange-100",
  "bg-amber-100",
  "bg-yellow-100",
  "bg-lime-100",
  "bg-green-100",
  "bg-emerald-100",
  "bg-teal-100",
  "bg-cyan-100",
  "bg-sky-100",
  "bg-blue-100",
  "bg-indigo-100",
  "bg-violet-100",
  "bg-purple-100",
  "bg-fuchsia-100",
  "bg-pink-100",
  "bg-rose-100",
] as const

export function groupDisplayName(item: GroupedTableItem): string {
  if (item.group_name) return item.group_name
  if (item.group_id === 0) return "(Ungrouped)"
  return `Missing group #${item.group_id}`
}

function compareText(left: string, right: string): number {
  return left.localeCompare(right, undefined, { sensitivity: "base" })
}

export function groupedTableRows<T extends GroupedTableItem>(items: readonly T[]): GroupedTableRow<T>[] {
  const sorted = [...items].sort((left, right) => {
    const leftUngrouped = left.group_id === 0
    const rightUngrouped = right.group_id === 0
    if (leftUngrouped !== rightUngrouped) return leftUngrouped ? 1 : -1

    const groupComparison = compareText(groupDisplayName(left), groupDisplayName(right))
    if (groupComparison !== 0) return groupComparison

    const nameComparison = compareText(left.name, right.name)
    return nameComparison !== 0 ? nameComparison : left.id - right.id
  })

  const colorsByGroup = new Map<number, string>()
  let nextColor = 0

  return sorted.map(item => {
    let backgroundClass = "bg-gray-100"
    if (item.group_id !== 0) {
      backgroundClass = colorsByGroup.get(item.group_id) ?? groupBackgroundClasses[nextColor++ % groupBackgroundClasses.length]
      colorsByGroup.set(item.group_id, backgroundClass)
    }

    return {
      item,
      groupLabel: groupDisplayName(item),
      backgroundClass,
    }
  })
}
