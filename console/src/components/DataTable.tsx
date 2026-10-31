import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type OnChangeFn,
  type PaginationState,
  type RowSelectionState,
  type SortingState,
} from "@tanstack/react-table";
import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { PAGE_SIZES } from "./pageSizes";

interface DataTableProps<T> {
  data: T[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  columns: ColumnDef<T, any>[];
  getRowId: (row: T) => string;
  sorting: SortingState;
  onSortingChange: OnChangeFn<SortingState>;
  pagination: PaginationState;
  onPaginationChange: OnChangeFn<PaginationState>;
  /** Sunucu tarafı sıralama ve sayfalama; verilirse toplam kayıt sayısıdır. */
  serverTotal?: number;
  rowSelection?: RowSelectionState;
  onRowSelectionChange?: OnChangeFn<RowSelectionState>;
  loading?: boolean;
  emptyText?: string;
  onRowClick?: (row: T) => void;
  label: string;
}

/**
 * Tüm listelerde kullanılan tablo: sütun başlığına tıklayarak sıralama, sayfalama ve
 * (isteğe bağlı) toplu seçim. serverTotal verilirse sıralama ve sayfalama sunucuda yapılır.
 */
export function DataTable<T>(props: DataTableProps<T>) {
  const { t } = useTranslation();
  const manual = props.serverTotal !== undefined;
  const selectable = props.rowSelection !== undefined;

  const columns = useMemo<ColumnDef<T>[]>(() => {
    if (!selectable) return props.columns;
    const select: ColumnDef<T> = {
      id: "_select",
      enableSorting: false,
      header: ({ table }) => (
        <input
          type="checkbox"
          className="checkbox"
          aria-label={t("table.selectAll")}
          checked={table.getIsAllPageRowsSelected()}
          ref={(el) => {
            if (el) el.indeterminate = table.getIsSomePageRowsSelected();
          }}
          onChange={table.getToggleAllPageRowsSelectedHandler()}
        />
      ),
      cell: ({ row }) => (
        <input
          type="checkbox"
          className="checkbox"
          aria-label={t("table.selectRow")}
          checked={row.getIsSelected()}
          onClick={(e) => e.stopPropagation()}
          onChange={row.getToggleSelectedHandler()}
        />
      ),
    };
    return [select, ...props.columns];
  }, [props.columns, selectable, t]);

  // TanStack Table kendi içinde önbellekleme yaptığı için React Compiler bu bileşeni atlar; davranış etkilenmez.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: props.data,
    columns,
    getRowId: props.getRowId,
    state: {
      sorting: props.sorting,
      pagination: props.pagination,
      ...(selectable ? { rowSelection: props.rowSelection } : {}),
    },
    onSortingChange: props.onSortingChange,
    onPaginationChange: props.onPaginationChange,
    onRowSelectionChange: props.onRowSelectionChange,
    enableRowSelection: selectable,
    manualSorting: manual,
    manualPagination: manual,
    rowCount: manual ? props.serverTotal : undefined,
    enableSortingRemoval: false,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: manual ? undefined : getSortedRowModel(),
    getPaginationRowModel: manual ? undefined : getPaginationRowModel(),
  });

  const total = manual ? (props.serverTotal ?? 0) : props.data.length;
  const { pageIndex, pageSize } = props.pagination;
  const from = total === 0 ? 0 : pageIndex * pageSize + 1;
  const to = Math.min(total, (pageIndex + 1) * pageSize);
  const rows = table.getRowModel().rows;

  return (
    <div className="data-table">
      <div className="table-wrap">
        <table className="table" aria-label={props.label} aria-busy={props.loading || undefined}>
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => {
                  const sorted = h.column.getIsSorted();
                  const canSort = h.column.getCanSort();
                  return (
                    <th
                      key={h.id}
                      className={h.id === "_select" ? "col-select" : undefined}
                      aria-sort={
                        sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined
                      }
                    >
                      {canSort ? (
                        <button
                          type="button"
                          className="th-sort"
                          onClick={h.column.getToggleSortingHandler()}
                          title={sorted === "asc" ? t("table.sortDesc") : t("table.sortAsc")}
                        >
                          {flexRender(h.column.columnDef.header, h.getContext())}
                          <span className={`sort-icon${sorted ? " active" : ""}`} aria-hidden="true">
                            {sorted === "desc" ? "▼" : "▲"}
                          </span>
                        </button>
                      ) : (
                        flexRender(h.column.columnDef.header, h.getContext())
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="table-empty">
                  {props.loading ? t("common.loading") : (props.emptyText ?? t("table.empty"))}
                </td>
              </tr>
            )}
            {rows.map((row) => (
              <tr
                key={row.id}
                className={`${props.onRowClick ? "clickable" : ""}${row.getIsSelected() ? " selected" : ""}`}
                onClick={props.onRowClick ? () => props.onRowClick!(row.original) : undefined}
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className={cell.column.id === "_select" ? "col-select" : undefined}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pager">
        <label className="pager-size">
          <span>{t("table.pageSize")}</span>
          <select
            className="select select-sm"
            value={pageSize}
            onChange={(e) => props.onPaginationChange({ pageIndex: 0, pageSize: Number(e.target.value) })}
          >
            {PAGE_SIZES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <span className="pager-range">{t("table.range", { from, to, total })}</span>
        <button
          type="button"
          className="icon-btn"
          aria-label={t("table.prev")}
          disabled={!table.getCanPreviousPage()}
          onClick={() => table.previousPage()}
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="m15 18-6-6 6-6" />
          </svg>
        </button>
        <button
          type="button"
          className="icon-btn"
          aria-label={t("table.next")}
          disabled={!table.getCanNextPage()}
          onClick={() => table.nextPage()}
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="m9 18 6-6-6-6" />
          </svg>
        </button>
      </div>
    </div>
  );
}
