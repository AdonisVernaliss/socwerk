<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, reportUrl } from '$lib/api';
  import { chooseLocale, translate, type MessageKey } from '$lib/i18n';
  import type {
    Alert,
    Decision,
    Detection,
    EventDetail,
    EventPage,
    InvestigationItem,
    Locale,
    ScenarioDetail,
    ScenarioSummary,
    Session
  } from '$lib/types';

  type View = 'overview' | 'events' | 'alerts' | 'detections' | 'assets' | 'users' | 'investigation' | 'report';

  const nav: Array<{ id: View; key: MessageKey }> = [
    { id: 'overview', key: 'overview' },
    { id: 'events', key: 'events' },
    { id: 'alerts', key: 'alerts' },
    { id: 'detections', key: 'detections' },
    { id: 'assets', key: 'assets' },
    { id: 'users', key: 'users' },
    { id: 'investigation', key: 'investigation' },
    { id: 'report', key: 'report' }
  ];

  let locale: Locale = 'en';
  let scenarios: ScenarioSummary[] = [];
  let session: Session | null = null;
  let scenario: ScenarioDetail | null = null;
  let eventPage: EventPage | null = null;
  let alerts: Alert[] = [];
  let detections: Detection[] = [];
  let selectedEvent: EventDetail | null = null;
  let eventPivots: Array<[string, string | undefined]> = [];
  let selectedAlertId = '';
  let activeView: View | 'scenarios' = 'scenarios';
  let busy = true;
  let error = '';
  let notice = '';
  let search = '';
  let query = '';
  let sourceFilter = '';
  let typeFilter = '';
  let severityFilter = '';
  let assetFilter = '';
  let userFilter = '';
  let mitreFilter = '';
  let detectionFilter = '';
  let alertFilter = '';
  let timeFrom = '';
  let timeTo = '';
  let sortBy = 'timestamp';
  let sortDirection = 'asc';
  let offset = 0;
  const pageSize = 25;
  let evidenceNote = '';
  let alertRationale = '';
  let itemKind: InvestigationItem['kind'] = 'note';
  let itemText = '';
  let itemEvidenceIds: string[] = [];
  let showSubmitDialog = false;
  let eventDrawer: HTMLDivElement;
  let confirmDialog: HTMLDivElement;
  let eventReturnFocus: HTMLElement | null = null;
  let submitReturnFocus: HTMLElement | null = null;
  let decision: Decision = blankDecision();

  $: selectedAlert = alerts.find((item) => item.id === selectedAlertId) ?? null;
  $: availableMitre = Array.from(
    new Set([
      ...detections.flatMap((item) => item.mitre),
      ...(eventPage?.facets.mitre ?? [])
    ])
  ).sort();
  $: activeScenarioSummary = scenarios.find((item) => item.id === session?.scenario_id);
  $: eventPivots = selectedEvent
    ? [
        ['user', selectedEvent.normalized.user_id],
        ['asset', selectedEvent.normalized.asset_id],
        ['source_ip', selectedEvent.normalized.source_ip],
        ['destination_ip', selectedEvent.normalized.destination_ip],
        ['domain', selectedEvent.normalized.domain],
        ['process_name', selectedEvent.normalized.process_name]
      ]
    : [];

  function blankDecision(): Decision {
    return {
      classification: 'benign',
      severity: 'low',
      affected_user_ids: [],
      affected_asset_ids: [],
      mitre: [],
      containment_action_ids: [],
      rationale: ''
    };
  }

  let t: (key: MessageKey) => string;
  let localized: (value: { en: string; de: string } | undefined) => string;
  $: t = (key) => translate(locale, key);
  $: localized = (value) => value?.[locale] ?? '';

  let label: (value: string) => string;
  $: label = (value) => {
    const known: Partial<Record<string, MessageKey>> = {
      benign: 'benign',
      false_positive: 'false_positive',
      confirmed_incident: 'confirmed_incident',
      foundation: 'foundation',
      intermediate: 'intermediate',
      advanced: 'advanced',
      active: 'active',
      submitted: 'submitted',
      new: 'new',
      in_progress: 'in_progress',
      escalated: 'escalated',
      workstation: 'workstation',
      server: 'server',
      identity: 'identity',
      network: 'network',
      cloud: 'cloud',
      informational: 'informational',
      low: 'low',
      medium: 'medium',
      high: 'high',
      critical: 'critical',
      affected_users: 'affectedUsers',
      affected_assets: 'affectedAssets',
      critical_evidence: 'criticalEvidence',
      mitre_mapping: 'mitreMapping',
      false_positive_handling: 'falsePositiveHandling',
      containment: 'containment',
      classification: 'classification',
      severity: 'severity'
    };
    return known[value] ? t(known[value]!) : value.replaceAll('_', ' ');
  };

  let formatTime: (value: string) => string;
  $: formatTime = (value) =>
    new Intl.DateTimeFormat(locale === 'de' ? 'de-DE' : 'en-GB', {
      dateStyle: 'short',
      timeStyle: 'medium',
      timeZone: 'UTC'
    }).format(new Date(value));

  function formatValue(value: unknown): string {
    return typeof value === 'string' ? value : JSON.stringify(value);
  }

  function setLocale(next: Locale): void {
    locale = next;
    localStorage.setItem('socwerk.locale', next);
    document.documentElement.lang = next;
  }

  async function initialize(): Promise<void> {
    busy = true;
    error = '';
    try {
      scenarios = await api<ScenarioSummary[]>('/api/scenarios');
      const savedSession = localStorage.getItem('socwerk.session');
      if (savedSession) {
        try {
          session = await api<Session>(`/api/sessions/${savedSession}`);
          activeView = 'overview';
          await loadWorkspace();
        } catch {
          localStorage.removeItem('socwerk.session');
          session = null;
        }
      }
    } catch {
      error = t('apiUnavailable');
    } finally {
      busy = false;
    }
  }

  async function startScenario(scenarioId: string): Promise<void> {
    busy = true;
    error = '';
    try {
      session = await api<Session>('/api/sessions', {
        method: 'POST',
        body: JSON.stringify({ scenario_id: scenarioId })
      });
      localStorage.setItem('socwerk.session', session.id);
      decision = blankDecision();
      activeView = 'overview';
      await loadWorkspace();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : t('apiUnavailable');
    } finally {
      busy = false;
    }
  }

  async function resumeCurrent(): Promise<void> {
    if (!session) return;
    try {
      activeView = 'overview';
      await loadWorkspace();
    } catch {
      error = t('apiUnavailable');
    }
  }

  async function loadWorkspace(): Promise<void> {
    if (!session) return;
    [scenario, alerts, detections] = await Promise.all([
      api<ScenarioDetail>(`/api/scenarios/${session.scenario_id}`),
      api<Alert[]>(`/api/sessions/${session.id}/alerts`),
      api<Detection[]>(`/api/sessions/${session.id}/detections`)
    ]);
    if (session.decision) decision = structuredClone(session.decision);
    await loadEvents();
  }

  async function refreshSession(): Promise<void> {
    if (!session) return;
    session = await api<Session>(`/api/sessions/${session.id}`);
  }

  async function loadEvents(reset = false): Promise<void> {
    if (!session) return;
    if (reset) offset = 0;
    const params = new URLSearchParams({
      limit: String(pageSize),
      offset: String(offset),
      sort: sortDirection,
      sort_by: sortBy
    });
    if (search) params.set('search', search);
    if (query) params.set('query', query);
    if (sourceFilter) params.set('source', sourceFilter);
    if (typeFilter) params.set('event_type', typeFilter);
    if (severityFilter) params.set('severity', severityFilter);
    if (assetFilter) params.set('asset', assetFilter);
    if (userFilter) params.set('user', userFilter);
    if (mitreFilter) params.set('mitre', mitreFilter);
    if (detectionFilter) params.set('detection', detectionFilter);
    if (alertFilter) params.set('alert', alertFilter);
    if (timeFrom) params.set('time_from', new Date(`${timeFrom}Z`).toISOString());
    if (timeTo) params.set('time_to', new Date(`${timeTo}Z`).toISOString());
    error = '';
    try {
      eventPage = await api<EventPage>(`/api/sessions/${session.id}/events?${params}`);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    }
  }

  async function inspectEvent(eventId: string): Promise<void> {
    if (!session) return;
    try {
      if (!selectedEvent) eventReturnFocus = document.activeElement as HTMLElement | null;
      selectedEvent = await api<EventDetail>(`/api/sessions/${session.id}/events/${eventId}`);
      evidenceNote = '';
      await tick();
      eventDrawer?.focus();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : t('apiUnavailable');
    }
  }

  async function preserveEvidence(): Promise<void> {
    if (!session || !selectedEvent) return;
    try {
      await api(`/api/sessions/${session.id}/evidence`, {
        method: 'POST',
        body: JSON.stringify({ event_id: selectedEvent.id, note: evidenceNote })
      });
      await refreshSession();
      notice = t('evidenceAdded');
      setTimeout(() => (notice = ''), 2500);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    }
  }

  async function removeEvidence(id: string): Promise<void> {
    if (!session) return;
    try {
      await api(`/api/sessions/${session.id}/evidence/${id}`, { method: 'DELETE' });
      await refreshSession();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : t('apiUnavailable');
    }
  }

  async function takeAlertAction(action: string): Promise<void> {
    if (!session || !selectedAlert || alertRationale.trim().length < 3) return;
    try {
      await api(`/api/sessions/${session.id}/alerts/${selectedAlert.id}/actions`, {
        method: 'POST',
        body: JSON.stringify({ action, rationale: alertRationale })
      });
      alerts = await api<Alert[]>(`/api/sessions/${session.id}/alerts`);
      await refreshSession();
      alertRationale = '';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    }
  }

  async function addItem(): Promise<void> {
    if (!session || itemText.trim().length < 2) return;
    try {
      await api(`/api/sessions/${session.id}/items/${itemKind}`, {
        method: 'POST',
        body: JSON.stringify({ text: itemText, evidence_event_ids: itemEvidenceIds })
      });
      itemText = '';
      itemEvidenceIds = [];
      await refreshSession();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : t('apiUnavailable');
    }
  }

  async function openSubmitDialog(): Promise<void> {
    submitReturnFocus = document.activeElement as HTMLElement | null;
    showSubmitDialog = true;
    await tick();
    confirmDialog?.focus();
  }

  async function closeEventDrawer(): Promise<void> {
    selectedEvent = null;
    await tick();
    eventReturnFocus?.focus();
  }

  async function closeSubmitDialog(): Promise<void> {
    showSubmitDialog = false;
    await tick();
    submitReturnFocus?.focus();
  }

  function trapFocus(event: KeyboardEvent, container: HTMLElement | undefined): void {
    if (event.key !== 'Tab' || !container) return;
    const focusable = Array.from(
      container.querySelectorAll<HTMLElement>(
        'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
    );
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function handleWindowKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      if (showSubmitDialog) closeSubmitDialog();
      else if (selectedEvent) closeEventDrawer();
      return;
    }
    trapFocus(event, showSubmitDialog ? confirmDialog : selectedEvent ? eventDrawer : undefined);
  }

  function toggle(list: string[], id: string): string[] {
    return list.includes(id) ? list.filter((item) => item !== id) : [...list, id];
  }

  async function saveDecision(): Promise<boolean> {
    if (!session || decision.rationale.trim().length < 10) return false;
    try {
      await api(`/api/sessions/${session.id}/decision`, {
        method: 'PUT',
        body: JSON.stringify(decision)
      });
      await refreshSession();
      notice = t('saveDecision');
      setTimeout(() => (notice = ''), 2500);
      return true;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : t('apiUnavailable');
      return false;
    }
  }

  async function submitInvestigation(): Promise<void> {
    if (!session) return;
    busy = true;
    try {
      if (!(await saveDecision())) return;
      const result = await api<{ session: Session }>(`/api/sessions/${session.id}/submit`, {
        method: 'POST'
      });
      session = result.session;
      showSubmitDialog = false;
      activeView = 'report';
    } catch (cause) {
      error = cause instanceof Error ? cause.message : String(cause);
    } finally {
      busy = false;
    }
  }

  function isEvidence(eventId: string): boolean {
    return session?.evidence.some((item) => item.event_id === eventId) ?? false;
  }

  function goToEvent(eventId: string): void {
    activeView = 'events';
    inspectEvent(eventId);
  }

  function pivot(field: string, value: string): void {
    activeView = 'events';
    query = `${field} = ${value}`;
    search = '';
    sourceFilter = '';
    typeFilter = '';
    severityFilter = '';
    assetFilter = '';
    userFilter = '';
    mitreFilter = '';
    detectionFilter = '';
    alertFilter = '';
    timeFrom = '';
    timeTo = '';
    selectedEvent = null;
    loadEvents(true);
  }

  onMount(() => {
    const stored = localStorage.getItem('socwerk.locale') as Locale | null;
    setLocale(stored === 'de' || stored === 'en' ? stored : chooseLocale(navigator.language));
    initialize();
  });
</script>

<svelte:head>
  <title>SOCWerk — Local SOC & Detection Engineering Lab</title>
</svelte:head>

<svelte:window on:keydown={handleWindowKeydown} />

{#if busy && scenarios.length === 0}
  <main class="loading-screen"><div class="spinner"></div><p>{t('loading')}</p></main>
{:else if activeView === 'scenarios' || !session || !scenario}
  <main class="landing">
    <header class="landing-header">
      <div class="brand-lockup">
        <div class="brand-mark" aria-hidden="true">SW</div>
        <div><h1>SOCWerk</h1><p>{t('appSubtitle')}</p></div>
      </div>
      <label class="language-control">{t('language')}
        <select bind:value={locale} on:change={(event) => setLocale(event.currentTarget.value as Locale)}>
          <option value="en">English</option><option value="de">Deutsch</option>
        </select>
      </label>
    </header>

    {#if error}
      <section class="error-banner" role="alert"><span>{error}</span><button on:click={initialize}>{t('retry')}</button></section>
    {/if}

    <section class="hero">
      <p class="eyebrow">{t('pipelineCaption')}</p>
      <h2>{t('chooseScenario')}</h2>
      <p>{t('chooseScenarioHelp')}</p>
    </section>

    {#if session && activeScenarioSummary}
      <section class="resume-card">
        <div><span class="status-dot"></span><strong>{localized(activeScenarioSummary.title)}</strong><small>{t('session')} · {label(session.status)}</small></div>
        <button class="primary" on:click={resumeCurrent}>{t('resume')}</button>
      </section>
    {/if}

    <section class="scenario-grid" aria-label={t('chooseScenario')}>
      {#each scenarios as item, index (item.id)}
        <article class="scenario-card">
          <div class="card-top"><span class="case-number">{t('caseLabel')} {String(index + 1).padStart(2, '0')}</span><span class="difficulty">{label(item.difficulty)}</span></div>
          <h3>{localized(item.title)}</h3>
          <p>{localized(item.description)}</p>
          <div class="scenario-stats">
            <span><strong>{item.event_count}</strong> {t('eventCount')}</span>
            <span><strong>{item.detection_count}</strong> {t('ruleCount')}</span>
            <span><strong>{item.asset_count}</strong> {t('assetCount')}</span>
          </div>
          <div class="card-footer"><span>{item.estimated_minutes} {t('minutes')}</span><button class="primary" on:click={() => startScenario(item.id)}>{t('start')}</button></div>
        </article>
      {/each}
    </section>
    <footer class="landing-footer">{t('localSafetyCaption')}</footer>
  </main>
{:else}
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand-lockup compact"><div class="brand-mark" aria-hidden="true">SW</div><div><strong>SOCWerk</strong><small>{t('appSubtitle')}</small></div></div>
      <button class="back-link" on:click={() => (activeView = 'scenarios')}>← {t('backToScenarios')}</button>
      <nav aria-label={t('investigationSections')}>
        {#each nav as item}
          <button class:active={activeView === item.id} aria-current={activeView === item.id ? 'page' : undefined} on:click={() => (activeView = item.id)}>
            <span class="nav-glyph" aria-hidden="true"></span>{t(item.key)}
            {#if item.id === 'alerts'}<span class="count">{alerts.length}</span>{/if}
            {#if item.id === 'investigation'}<span class="count">{session.evidence.length}</span>{/if}
          </button>
        {/each}
      </nav>
      <div class="sidebar-status"><span class="status-dot"></span><div><small>{t('session')}</small><strong>{label(session.status)}</strong></div></div>
    </aside>

    <div class="workspace">
      <header class="workspace-header">
        <div><p class="eyebrow">{scenario.metadata.id} · v{scenario.metadata.version}</p><h1>{localized(scenario.metadata.title)}</h1></div>
        <div class="header-actions">
          <span class="severity-badge {session.status}">{label(session.status)}</span>
          <label class="language-control sr-label"><span>{t('language')}</span><select bind:value={locale} on:change={(event) => setLocale(event.currentTarget.value as Locale)}><option value="en">EN</option><option value="de">DE</option></select></label>
        </div>
      </header>

      <div class="mobile-nav"><label><span class="sr-only">{t('section')}</span><select bind:value={activeView}>{#each nav as item}<option value={item.id}>{t(item.key)}</option>{/each}</select></label></div>

      {#if error}<div class="error-banner compact-error" role="alert"><span>{error}</span><button aria-label={t('close')} on:click={() => (error = '')}>×</button></div>{/if}
      {#if notice}<div class="notice" role="status">{notice}</div>{/if}

      <main class="content">
        {#if activeView === 'overview'}
          <section class="overview-grid">
            <article class="panel intro-panel"><p class="eyebrow">{t('overview')}</p><h2>{localized(scenario.metadata.title)}</h2><p class="lead">{localized(scenario.metadata.description)}</p><div class="metrics"><div><strong>{scenario.event_count}</strong><span>{t('events')}</span></div><div><strong>{alerts.length}</strong><span>{t('alerts')}</span></div><div><strong>{scenario.detection_count}</strong><span>{t('detections')}</span></div><div><strong>{session.evidence.length}</strong><span>{t('evidence')}</span></div></div></article>
            <article class="panel"><h2>{t('objectives')}</h2><ul class="objective-list">{#each scenario.metadata.learning_objectives as objective}<li>{localized(objective)}</li>{/each}</ul></article>
            <article class="panel pipeline-panel"><h2>{t('pipeline')}</h2><div class="pipeline"><span>{t('rawStep')}</span><i>→</i><span>{t('normalizedStep')}</span><i>→</i><span>{t('detectionStep')}</span><i>→</i><span>{t('alertStep')}</span><i>→</i><span>{t('triageStep')}</span><i>→</i><span>{t('report')}</span></div></article>
            <article class="panel context-panel"><h2>{t('germanyContext')}</h2><p>{t('germanyText')}</p></article>
          </section>
        {:else if activeView === 'events'}
          <section aria-labelledby="events-heading">
            <div class="section-heading"><div><p class="eyebrow">{t('eventExplorer')}</p><h2 id="events-heading">{t('events')}</h2></div><span>{eventPage?.total ?? 0} {t('eventCount')}</span></div>
            <form class="filters panel" on:submit|preventDefault={() => loadEvents(true)}>
              <label class="search-field"><span>{t('search')}</span><input bind:value={search} placeholder={t('searchPlaceholder')} /></label>
              <label class="query-field"><span>{t('query')}</span><input bind:value={query} placeholder='source = sysmon and severity = high' /></label>
              <div class="filter-row">
                <label><span>{t('source')}</span><select bind:value={sourceFilter}><option value="">{t('allSources')}</option>{#each eventPage?.facets.sources ?? [] as source}<option value={source}>{source}</option>{/each}</select></label>
                <label><span>{t('type')}</span><select bind:value={typeFilter}><option value="">{t('allTypes')}</option>{#each eventPage?.facets.event_types ?? [] as eventType}<option value={eventType}>{eventType}</option>{/each}</select></label>
                <label><span>{t('severity')}</span><select bind:value={severityFilter}><option value="">{t('allSeverities')}</option>{#each eventPage?.facets.severities ?? [] as severity}<option value={severity}>{label(severity)}</option>{/each}</select></label>
                <label><span>{t('assets')}</span><select bind:value={assetFilter}><option value="">{t('allAssets')}</option>{#each scenario.assets as asset}<option value={asset.id}>{asset.hostname}</option>{/each}</select></label>
                <label><span>{t('users')}</span><select bind:value={userFilter}><option value="">{t('allUsers')}</option>{#each scenario.users as user}<option value={user.id}>{user.display_name}</option>{/each}</select></label>
                <label><span>{t('mitreMapping')}</span><select bind:value={mitreFilter}><option value="">{t('allMitre')}</option>{#each eventPage?.facets.mitre ?? [] as technique}<option value={technique}>{technique}</option>{/each}</select></label>
                <label><span>{t('detections')}</span><select bind:value={detectionFilter}><option value="">{t('allDetections')}</option>{#each detections as rule}<option value={rule.id}>{localized(rule.title)}</option>{/each}</select></label>
                <label><span>{t('alerts')}</span><select bind:value={alertFilter}><option value="">{t('allAlerts')}</option>{#each alerts as alert}<option value={alert.id}>{localized(alert.title)} · {alert.event_ids[0]}</option>{/each}</select></label>
                <label><span>{t('timeFrom')}</span><input type="datetime-local" bind:value={timeFrom} /></label>
                <label><span>{t('timeTo')}</span><input type="datetime-local" bind:value={timeTo} /></label>
                <label><span>{t('sortBy')}</span><select bind:value={sortBy}><option value="timestamp">{t('time')}</option><option value="severity">{t('severity')}</option><option value="source">{t('source')}</option><option value="event_type">{t('type')}</option></select></label>
                <label><span>{t('sortDirection')}</span><select bind:value={sortDirection}><option value="asc">{t('ascending')}</option><option value="desc">{t('descending')}</option></select></label>
                <button class="primary" type="submit">{t('apply')}</button>
                <button class="secondary" type="button" on:click={() => { search=''; query=''; sourceFilter=''; typeFilter=''; severityFilter=''; assetFilter=''; userFilter=''; mitreFilter=''; detectionFilter=''; alertFilter=''; timeFrom=''; timeTo=''; sortBy='timestamp'; sortDirection='asc'; loadEvents(true); }}>{t('clear')}</button>
              </div>
              <small>{t('queryHelp')}</small>
            </form>
            <div class="table-panel">
              <div class="table-scroll">
                <table>
                  <thead><tr><th>{t('time')}</th><th>{t('source')}</th><th>{t('type')}</th><th>{t('severity')}</th><th>{t('entity')}</th><th>{t('summary')}</th><th><span class="sr-only">{t('inspect')}</span></th></tr></thead>
                  <tbody>
                    {#each eventPage?.items ?? [] as event (event.id)}
                      <tr class:evidence-row={isEvidence(event.id)}><td class="mono time-cell">{formatTime(event.timestamp)}</td><td><span class="source-chip">{event.source}</span></td><td class="mono">{event.event_type}</td><td><span class="severity-badge {event.severity}">{label(event.severity)}</span></td><td class="mono">{event.asset_id ?? event.user_id ?? event.source_ip ?? '—'}</td><td class="summary-cell"><strong>{event.summary}</strong><small>{event.id} {event.mitre?.length ? `· ${event.mitre.join(', ')}` : ''}</small></td><td><button class="icon-button" aria-label={`${t('inspect')} ${event.id}`} on:click={() => inspectEvent(event.id)}>→</button></td></tr>
                    {:else}
                      <tr><td colspan="7" class="empty-state">{t('noEvents')}</td></tr>
                    {/each}
                  </tbody>
                </table>
              </div>
              <div class="pagination"><span>{t('showing')} {eventPage && eventPage.total ? offset + 1 : 0}–{Math.min(offset + pageSize, eventPage?.total ?? 0)} {t('of')} {eventPage?.total ?? 0}</span><div><button class="secondary" disabled={offset === 0} on:click={() => { offset = Math.max(0, offset - pageSize); loadEvents(); }}>{t('previous')}</button><button class="secondary" disabled={offset + pageSize >= (eventPage?.total ?? 0)} on:click={() => { offset += pageSize; loadEvents(); }}>{t('next')}</button></div></div>
            </div>
          </section>
        {:else if activeView === 'alerts'}
          <section>
            <div class="section-heading"><div><p class="eyebrow">{t('triageQueue')}</p><h2>{t('alerts')}</h2></div><span>{alerts.length}</span></div>
            <div class="split-view">
              <div class="alert-list panel">
                {#each alerts as alert (alert.id)}
                  <button class:active={selectedAlertId === alert.id} on:click={() => { selectedAlertId = alert.id; alertRationale = alert.rationale; }}><span class="severity-marker {alert.severity}"></span><div><strong>{localized(alert.title)}</strong><small>{formatTime(alert.timestamp)} · {alert.event_ids.join(', ')}</small></div><span class="state-chip">{label(alert.state)}</span></button>
                {:else}<p class="empty-state">{t('noAlerts')}</p>{/each}
              </div>
              <div class="panel detail-panel">
                {#if selectedAlert}
                  <div class="detail-heading"><div><span class="severity-badge {selectedAlert.severity}">{label(selectedAlert.severity)}</span><h3>{localized(selectedAlert.title)}</h3><code>{selectedAlert.rule_id}</code></div></div>
                  <h4>{t('whyFired')}</h4>
                  <div class="match-grid">{#each selectedAlert.match_details as match}<div class:matched={match.matched}><code>{match.field}</code><span>{match.operator}</span><strong>{formatValue(match.expected)}</strong><small>{t('actualValue')}: {formatValue(match.actual)}</small></div>{/each}</div>
                  <h4>{t('matchedEvents')}</h4><div class="chip-row">{#each selectedAlert.event_ids as eventId}<button class="entity-chip" on:click={() => goToEvent(eventId)}>{eventId} ↗</button>{/each}{#each selectedAlert.mitre as technique}<span class="mitre-chip">{technique}</span>{/each}</div>
                  <div class="context-callout"><strong>{t('falsePositiveContext')}</strong><p>{localized(selectedAlert.false_positive_context)}</p></div>
                  {#if session.status === 'active' && !['benign','false_positive','confirmed_incident'].includes(selectedAlert.state)}
                    <label><span>{t('rationale')}</span><textarea bind:value={alertRationale} rows="3" placeholder={t('rationale')}></textarea></label>
                    <div class="action-row">
                      {#if selectedAlert.state === 'new'}<button class="primary" disabled={alertRationale.trim().length < 3} on:click={() => takeAlertAction('begin_triage')}>{t('beginTriage')}</button>{:else}{#if selectedAlert.state !== 'escalated'}<button class="secondary" disabled={alertRationale.trim().length < 3} on:click={() => takeAlertAction('escalate')}>{t('escalate')}</button>{/if}<button class="secondary" disabled={alertRationale.trim().length < 3} on:click={() => takeAlertAction('mark_benign')}>{t('markBenign')}</button><button class="secondary" disabled={alertRationale.trim().length < 3} on:click={() => takeAlertAction('mark_false_positive')}>{t('markFalsePositive')}</button><button class="danger" disabled={alertRationale.trim().length < 3} on:click={() => takeAlertAction('confirm')}>{t('confirmIncident')}</button>{/if}
                    </div>
                  {:else if selectedAlert.rationale}<div class="analyst-decision"><strong>{label(selectedAlert.state)}</strong><p>{selectedAlert.rationale}</p></div>{/if}
                {:else}<div class="empty-state">{t('inspect')} {t('alerts').toLowerCase()}</div>{/if}
              </div>
            </div>
          </section>
        {:else if activeView === 'detections'}
          <section><div class="section-heading"><div><p class="eyebrow">{t('ruleCatalog')}</p><h2>{t('detections')}</h2></div><span>{detections.length}</span></div><div class="rule-list">{#each detections as rule}<details class="panel rule-card"><summary><span class="severity-marker {rule.severity}"></span><div><strong>{localized(rule.title)}</strong><small>{rule.id} · {rule.mitre.join(', ')}</small></div><span class="severity-badge {rule.severity}">{label(rule.severity)}</span></summary><div class="rule-body"><p>{localized(rule.description)}</p><h4>{t('conditions')} ({rule.match.toUpperCase()})</h4><div class="condition-list">{#each rule.conditions as condition}<code>{condition.field} {condition.operator} {formatValue(condition.value)}</code>{/each}</div><div class="context-callout"><strong>{t('falsePositiveContext')}</strong><p>{localized(rule.false_positive_context)}</p></div><h4>{t('sigma')}</h4><pre>{rule.sigma}</pre></div></details>{/each}</div></section>
        {:else if activeView === 'assets'}
          <section><div class="section-heading"><div><p class="eyebrow">{t('entityInventory')}</p><h2>{t('assets')}</h2></div><span>{scenario.assets.length}</span></div><div class="entity-grid">{#each scenario.assets as asset}<article class="panel entity-card"><div><span class="asset-icon" aria-hidden="true">▣</span><span class="severity-badge {asset.criticality}">{label(asset.criticality)}</span></div><h3>{asset.hostname}</h3><code>{asset.id}</code><dl><div><dt>{t('type')}</dt><dd>{label(asset.asset_type)}</dd></div><div><dt>{t('operatingSystem')}</dt><dd>{asset.operating_system ?? '—'}</dd></div><div><dt>{t('owner')}</dt><dd>{asset.owner_user_id ?? '—'}</dd></div></dl><button class="secondary" on:click={() => pivot('asset', asset.id)}>{t('events')} ↗</button></article>{/each}</div></section>
        {:else if activeView === 'users'}
          <section><div class="section-heading"><div><p class="eyebrow">{t('identityDirectory')}</p><h2>{t('users')}</h2></div><span>{scenario.users.length}</span></div><div class="entity-grid">{#each scenario.users as user}<article class="panel entity-card"><div class="user-avatar" aria-hidden="true">{user.display_name.split(' ').slice(-1)[0]}</div><h3>{user.display_name}</h3><code>{user.id}</code><dl><div><dt>{t('department')}</dt><dd>{user.department}</dd></div><div><dt>{t('role')}</dt><dd>{user.role}</dd></div></dl><div class="baseline"><strong>{t('baseline')}</strong><p>{localized(user.baseline)}</p></div><button class="secondary" on:click={() => pivot('user', user.id)}>{t('events')} ↗</button></article>{/each}</div></section>
        {:else if activeView === 'investigation'}
          <section><div class="section-heading"><div><p class="eyebrow">{t('analystWorkspace')}</p><h2>{t('investigation')}</h2></div><span>{session.evidence.length} {t('evidence').toLowerCase()}</span></div>
            <div class="investigation-layout">
              <article class="panel"><h3>{t('evidence')}</h3>{#each session.evidence as item}<div class="evidence-item"><button on:click={() => goToEvent(item.event_id)}><code>{item.event_id}</code><span>{item.note || '—'}</span></button>{#if session.status === 'active'}<button class="remove-button" aria-label={`${t('remove')} ${item.event_id}`} on:click={() => removeEvidence(item.id)}>×</button>{/if}</div>{:else}<p class="empty-state">{t('noEvidence')}</p>{/each}</article>
              <article class="panel"><h3>{t('recordedItems')}</h3>{#if session.status === 'active'}<div class="compose-item"><select bind:value={itemKind}><option value="note">{t('note')}</option><option value="hypothesis">{t('hypothesis')}</option><option value="finding">{t('finding')}</option></select><textarea bind:value={itemText} rows="3" placeholder={t('itemPlaceholder')}></textarea><button class="primary" disabled={itemText.trim().length < 2} on:click={addItem}>{t('add')}</button>{#if session.evidence.length}<div class="item-evidence"><span>{t('evidence')}</span>{#each session.evidence as evidence}<label><input type="checkbox" checked={itemEvidenceIds.includes(evidence.event_id)} on:change={() => itemEvidenceIds = toggle(itemEvidenceIds, evidence.event_id)} /> {evidence.event_id}</label>{/each}</div>{/if}</div>{/if}{#each session.items as item}<div class="work-item"><span class="item-kind">{t(item.kind)}</span><p>{item.text}</p>{#if item.evidence_event_ids.length}<small>{item.evidence_event_ids.join(', ')}</small>{/if}</div>{/each}</article>
            </div>
              <article class="panel decision-panel"><h3>{t('decision')}</h3><div class="decision-grid"><label><span>{t('classification')}</span><select bind:value={decision.classification} disabled={session.status === 'submitted'}><option value="benign">{t('benign')}</option><option value="false_positive">{t('false_positive')}</option><option value="confirmed_incident">{t('confirmed_incident')}</option></select></label><label><span>{t('severity')}</span><select bind:value={decision.severity} disabled={session.status === 'submitted'}><option value="low">{t('low')}</option><option value="medium">{t('medium')}</option><option value="high">{t('high')}</option><option value="critical">{t('critical')}</option></select></label></div>
              <fieldset disabled={session.status === 'submitted'}><legend>{t('affectedUsers')}</legend><div class="check-grid">{#each scenario.users as user}<label class="check-card"><input type="checkbox" checked={decision.affected_user_ids.includes(user.id)} on:change={() => decision.affected_user_ids = toggle(decision.affected_user_ids, user.id)} /><span><strong>{user.display_name}</strong><small>{user.id}</small></span></label>{/each}</div></fieldset>
              <fieldset disabled={session.status === 'submitted'}><legend>{t('affectedAssets')}</legend><div class="check-grid">{#each scenario.assets as asset}<label class="check-card"><input type="checkbox" checked={decision.affected_asset_ids.includes(asset.id)} on:change={() => decision.affected_asset_ids = toggle(decision.affected_asset_ids, asset.id)} /><span><strong>{asset.hostname}</strong><small>{asset.id}</small></span></label>{/each}</div></fieldset>
              <fieldset disabled={session.status === 'submitted'}><legend>{t('mitreMapping')}</legend><div class="check-grid techniques">{#each availableMitre as technique}<label class="check-card"><input type="checkbox" checked={decision.mitre.includes(technique)} on:change={() => decision.mitre = toggle(decision.mitre, technique)} /><span><strong>{technique}</strong></span></label>{/each}</div></fieldset>
              <fieldset disabled={session.status === 'submitted'}><legend>{t('containment')}</legend><div class="check-grid">{#each scenario.containment_options as option}<label class="check-card rich"><input type="checkbox" checked={decision.containment_action_ids.includes(option.id)} on:change={() => decision.containment_action_ids = toggle(decision.containment_action_ids, option.id)} /><span><strong>{localized(option.label)}</strong><small>{localized(option.description)}</small></span></label>{/each}</div></fieldset>
              <label><span>{t('rationale')}</span><textarea bind:value={decision.rationale} disabled={session.status === 'submitted'} rows="5" placeholder={t('decisionRationale')}></textarea></label>
              {#if session.status === 'active'}<div class="decision-actions"><button class="secondary" disabled={decision.rationale.trim().length < 10} on:click={saveDecision}>{t('saveDecision')}</button><div><small>{t('submitWarning')}</small><button class="danger" disabled={decision.rationale.trim().length < 10} on:click={openSubmitDialog}>{t('submitInvestigation')}</button></div></div>{/if}
            </article>
          </section>
        {:else if activeView === 'report'}
          <section><div class="section-heading"><div><p class="eyebrow">{t('incidentReport')}</p><h2>{t('report')}</h2></div></div>
            {#if session.status !== 'submitted' || !session.assessment}<article class="panel locked-report"><div class="lock-icon">◇</div><h3>{t('reportLocked')}</h3><button class="primary" on:click={() => (activeView = 'investigation')}>{t('decision')} →</button></article>{:else}<div class="report-layout"><article class="panel score-card"><div class="score-ring" style={`--score:${session.assessment.score * 3.6}deg`}><div><strong>{session.assessment.score}</strong><span>/ 100</span></div></div><h3>{t('assessment')}</h3><div class="score-breakdown">{#each Object.entries(session.assessment.breakdown) as [key, value]}<div><span>{label(key)}</span><strong>{value}</strong></div>{/each}</div></article><article class="panel outcome-card"><span class="severity-badge {session.assessment.expected.severity}">{label(session.assessment.expected.severity)}</span><h3>{t('expectedOutcome')}: {label(session.assessment.expected.classification)}</h3><p>{localized(session.assessment.expected.explanation)}</p><h4>{t('missedEvidence')}</h4><div class="chip-row">{#each session.assessment.feedback.missed_critical_evidence as id}<button class="entity-chip" on:click={() => goToEvent(id)}>{id}</button>{:else}<span>—</span>{/each}</div><h4>{t('objectives')}</h4><ul class="objective-list">{#each session.assessment.expected.lessons as lesson}<li>{localized(lesson)}</li>{/each}</ul><div class="export-row"><a class="primary" href={reportUrl(session.id, 'markdown')}>{t('exportMarkdown')}</a><a class="secondary" href={reportUrl(session.id, 'json')}>{t('exportJson')}</a><a class="secondary" href={reportUrl(session.id, 'html')}>{t('exportHtml')}</a></div></article></div>{/if}
          </section>
        {/if}
      </main>
    </div>
  </div>
{/if}

{#if selectedEvent}
  <div class="drawer-backdrop" role="presentation" on:click={(event) => { if (event.currentTarget === event.target) closeEventDrawer(); }}>
    <div class="event-drawer" role="dialog" aria-modal="true" aria-labelledby="event-title" tabindex="-1" bind:this={eventDrawer}>
      <header><div><p class="eyebrow">{selectedEvent.id}</p><h2 id="event-title">{selectedEvent.normalized.summary}</h2></div><button class="close-button" aria-label={t('close')} on:click={closeEventDrawer}>×</button></header>
      <div class="drawer-meta"><span class="severity-badge {selectedEvent.normalized.severity}">{label(selectedEvent.normalized.severity)}</span><span class="source-chip">{selectedEvent.normalized.source}</span><time>{formatTime(selectedEvent.normalized.timestamp)}</time></div>
      <div class="drawer-pivots">
        {#each eventPivots as [field, value]}
          {#if value}<button class="entity-chip" on:click={() => pivot(field, value)}>{t('pivot')}: {value} ↗</button>{/if}
        {/each}
      </div>
      <div class="telemetry-compare"><section><h3>{t('raw')}</h3><pre>{typeof selectedEvent.raw === 'string' ? selectedEvent.raw : JSON.stringify(selectedEvent.raw, null, 2)}</pre></section><section><h3>{t('normalized')}</h3><pre>{JSON.stringify(selectedEvent.normalized, null, 2)}</pre></section></div>
      <section class="drawer-section"><h3>{t('whyFired')}</h3>{#each selectedEvent.alerts as alert}<div class="mini-alert"><strong>{localized(alert.title)}</strong><div class="condition-list">{#each alert.match_details.filter((item) => item.matched) as match}<code>{match.field} {match.operator} {formatValue(match.expected)}</code>{/each}</div></div>{:else}<p class="empty-state">—</p>{/each}</section>
      <section class="drawer-section"><h3>{t('related')}</h3>{#each selectedEvent.related as related}<button class="related-item" on:click={() => inspectEvent(related.event_id)}><span><code>{related.event_id}</code><strong>{related.summary}</strong><small>{t('relatedBecause')}: {related.reasons.join(' + ')}</small></span><b>{related.strength}%</b></button>{:else}<p class="empty-state">—</p>{/each}</section>
      {#if session?.status === 'active'}<footer><label><span>{t('evidenceNote')}</span><input bind:value={evidenceNote} /></label><button class="primary" disabled={isEvidence(selectedEvent.id)} on:click={preserveEvidence}>{isEvidence(selectedEvent.id) ? t('evidenceAdded') : t('addEvidence')}</button></footer>{/if}
    </div>
  </div>
{/if}

{#if showSubmitDialog}
  <div class="dialog-backdrop" role="presentation"><div class="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-description" tabindex="-1" bind:this={confirmDialog}><p class="eyebrow">{t('finalDecision')}</p><h2 id="confirm-title">{t('submitInvestigation')}?</h2><p id="confirm-description">{t('submitWarning')}</p><div><button class="secondary" on:click={closeSubmitDialog}>{t('close')}</button><button class="danger" on:click={submitInvestigation}>{t('submitInvestigation')}</button></div></div></div>
{/if}
