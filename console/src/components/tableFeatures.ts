import {
  createColumnHelper,
  createPaginatedRowModel,
  createSortedRowModel,
  rowPaginationFeature,
  rowSelectionFeature,
  rowSortingFeature,
  sortFn_alphanumeric,
  sortFn_basic,
  sortFn_datetime,
  sortFn_text,
  tableFeatures,
  type RowData,
} from "@tanstack/react-table";

/**
 * Tüm tabloların kullandığı TanStack Table özellikleri: sıralama, sayfalama ve satır seçimi.
 * Otomatik sıralama metin, sayı/metin karışık ve tarih değerleri için kayıtlı işlevleri seçer.
 */
export const features = tableFeatures({
  rowSortingFeature,
  rowPaginationFeature,
  rowSelectionFeature,
  sortedRowModel: createSortedRowModel(),
  paginatedRowModel: createPaginatedRowModel(),
  sortFns: {
    alphanumeric: sortFn_alphanumeric,
    text: sortFn_text,
    datetime: sortFn_datetime,
    basic: sortFn_basic,
  },
});

export type Features = typeof features;

/** columnHelper, DataTable'ın özellikleriyle tiplenmiş sütun yardımcısını döner. */
export function columnHelper<T extends RowData>() {
  return createColumnHelper<Features, T>();
}
