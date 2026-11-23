import React, { useEffect, useId, useRef, useState } from 'react'
import { Plus, Search } from 'lucide-react'

type AddressType = 'A' | 'AAAA'
type RecordDraft = {
  domain: string
  value: string
}

const emptyRecord: RecordDraft = { domain: '', value: '' }

function addressType(value: string): AddressType | undefined {
  if (
    /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value) &&
    value.split('.').every((part) => Number(part) <= 255)
  )
    return 'A'
  if (value.includes(':') && /^[0-9a-f:.]+$/i.test(value)) {
    // Brackets force the browser's URL parser to validate an IPv6 literal.
    try {
      new URL('http://[' + value + ']/')
      return 'AAAA'
    } catch {
      return undefined
    }
  }
}

function splitRecord(row: string) {
  const [domain = '', value = ''] = row.trim().split(/\s+/)
  return { domain, value }
}

function normalizedDomain(domain: string) {
  return domain.toLowerCase().replace(/\.$/, '')
}

function validateRecord(
  draft: RecordDraft,
  rows: string[],
  editedIndex?: number,
) {
  const domain = draft.domain.replace(/\.$/, '')
  if (
    domain.length > 253 ||
    !domain
      .replace(/^\*\./, '')
      .split('.')
      .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))
  )
    return '请输入有效域名，例如 nas.example.com 或 *.example.com。'

  const actualType = addressType(draft.value)
  if (!actualType) return '请输入有效的 IPv4 或 IPv6 地址。'

  const duplicate = rows.some((row, index) => {
    if (index === editedIndex) return false
    const record = splitRecord(row)
    return (
      normalizedDomain(record.domain) === domain.toLowerCase() &&
      addressType(record.value) === actualType
    )
  })
  if (duplicate) return '该域名已存在 ' + actualType + ' 记录。'
}

function RecordFields({
  draft,
  onChange,
}: {
  draft: RecordDraft
  onChange: (draft: RecordDraft) => void
}) {
  const id = useId()
  return (
    <>
      <div className="field">
        <label htmlFor={id + '-domain'}>域名</label>
        <input
          id={id + '-domain'}
          required
          spellCheck={false}
          autoComplete="off"
          placeholder="nas.example.com"
          value={draft.domain}
          onChange={(event) =>
            onChange({ ...draft, domain: event.target.value })
          }
        />
      </div>
      <div className="field">
        <label htmlFor={id + '-value'}>键值</label>
        <input
          id={id + '-value'}
          required
          spellCheck={false}
          autoComplete="off"
          placeholder="IPv4 或 IPv6 地址"
          value={draft.value}
          onChange={(event) =>
            onChange({ ...draft, value: event.target.value })
          }
        />
      </div>
    </>
  )
}

export function HostRecords({
  rows,
  onChange,
}: {
  rows: string[]
  onChange: (rows: string[]) => void
}) {
  const [filter, setFilter] = useState('')
  const [draft, setDraft] = useState(emptyRecord)
  const [error, setError] = useState('')
  const [action, setAction] = useState<{
    kind: 'edit' | 'delete'
    index: number
    row: string
  } | null>(null)
  const [editDraft, setEditDraft] = useState(emptyRecord)
  const [dialogError, setDialogError] = useState('')
  const dialog = useRef<HTMLDialogElement>(null)
  const titleId = useId()
  const descriptionId = useId()

  useEffect(() => {
    if (action && dialog.current && !dialog.current.open)
      dialog.current.showModal()
  }, [action])

  const selected = action ? splitRecord(action.row) : null
  const query = filter.trim().toLowerCase()
  const visibleRows = rows
    .map((row, index) => ({ row, index }))
    .filter(({ row }) => row.toLowerCase().includes(query))

  function addRecord(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const record = {
      ...draft,
      domain: draft.domain.trim(),
      value: draft.value.trim(),
    }
    const issue = validateRecord(record, rows)
    if (issue) {
      setError(issue)
      return
    }
    onChange([...rows, record.domain + ' ' + record.value])
    setDraft(emptyRecord)
    setFilter('')
    setError('')
  }

  function openRecord(kind: 'edit' | 'delete', index: number, row: string) {
    setDialogError('')
    setEditDraft({ ...splitRecord(row) })
    setAction({ kind, index, row })
  }

  function confirmRecord(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!action) return
    const { index, kind, row } = action
    if (rows[index] !== row) {
      setDialogError('记录已变更，请关闭后重新选择。')
      return
    }
    if (kind === 'delete') {
      onChange(rows.filter((_, i) => i !== index))
    } else {
      const record = {
        ...editDraft,
        domain: editDraft.domain.trim(),
        value: editDraft.value.trim(),
      }
      const issue = validateRecord(record, rows, index)
      if (issue) {
        setDialogError(issue)
        return
      }
      onChange(
        rows.map((value, i) =>
          i === index ? record.domain + ' ' + record.value : value,
        ),
      )
      setFilter('')
    }
    dialog.current?.close()
  }

  return (
    <fieldset className="wide nested host-records">
      <legend>自定义域名解析</legend>
      <form className="host-record-form" onSubmit={addRecord}>
        <RecordFields
          draft={draft}
          onChange={(next) => {
            setDraft(next)
            setError('')
          }}
        />
        <button type="submit" className="button primary">
          <Plus size={15} aria-hidden="true" /> 添加解析记录
        </button>
      </form>
      {error && (
        <p className="host-record-error" role="alert">
          {error}
        </p>
      )}
      <p className="host-record-hint">
        根据键值自动识别 A 或
        AAAA，每个域名可各设一条。修改后点击「保存并应用」生效。 *.abc.com
        匹配各级子域名，abc.com
        本身需单独配置。精确域名优先，其次匹配最长的通配后缀。
      </p>
      <div className="host-record-list">
        <div className="host-record-toolbar">
          <span>
            {query ? visibleRows.length + ' / ' : ''}
            {rows.length} 条记录
          </span>
          <div className="field host-record-search">
            <Search size={15} aria-hidden="true" />
            <input
              type="search"
              aria-label="查找解析记录"
              placeholder="查找域名或 IP"
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
            />
          </div>
        </div>
        <div className="host-record-table">
          <table aria-label="自定义解析记录">
            <thead>
              <tr>
                <th scope="col">域名</th>
                <th scope="col">键值</th>
                <th scope="col">类型</th>
                <th scope="col">操作</th>
              </tr>
            </thead>
            <tbody>
              {visibleRows.map(({ row, index }) => {
                const { domain, value } = splitRecord(row)
                return (
                  <tr key={index}>
                    <td>{domain}</td>
                    <td>{value}</td>
                    <td>
                      <span className="host-record-type">
                        {addressType(value) || '—'}
                      </span>
                    </td>
                    <td>
                      <div className="host-record-actions">
                        <button
                          type="button"
                          className="button tertiary small"
                          onClick={() => openRecord('edit', index, row)}
                        >
                          编辑
                        </button>
                        <button
                          type="button"
                          className="button tertiary small host-record-delete"
                          onClick={() => openRecord('delete', index, row)}
                        >
                          删除
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
              {!visibleRows.length && (
                <tr>
                  <td colSpan={4} className="host-record-empty">
                    {rows.length
                      ? '没有匹配的解析记录。'
                      : '暂无自定义解析记录。'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
      <dialog
        ref={dialog}
        className="modal host-record-dialog"
        aria-labelledby={titleId}
        aria-describedby={action?.kind === 'delete' ? descriptionId : undefined}
        onClose={() => setAction(null)}
      >
        {action && (
          <form onSubmit={confirmRecord}>
            <h2 id={titleId}>
              {action.kind === 'edit' ? '编辑解析记录' : '删除解析记录？'}
            </h2>
            {action.kind === 'edit' ? (
              <div className="host-record-edit-fields">
                <RecordFields
                  draft={editDraft}
                  onChange={(next) => {
                    setEditDraft(next)
                    setDialogError('')
                  }}
                />
              </div>
            ) : (
              <p id={descriptionId}>
                将从草稿中删除 <strong>{selected?.domain}</strong> 指向{' '}
                <strong>{selected?.value}</strong> 的记录。
              </p>
            )}
            {dialogError && (
              <p className="host-record-error" role="alert">
                {dialogError}
              </p>
            )}
            <div className="host-record-dialog-actions">
              <button
                type="button"
                className="button tertiary"
                onClick={() => dialog.current?.close()}
              >
                取消
              </button>
              <button
                type="submit"
                className={
                  'button ' +
                  (action.kind === 'edit'
                    ? 'primary'
                    : 'host-record-confirm-delete')
                }
              >
                {action.kind === 'edit' ? '保存修改' : '确认删除'}
              </button>
            </div>
          </form>
        )}
      </dialog>
    </fieldset>
  )
}
