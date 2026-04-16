package ui

import (
	"fmt"
	"strings"
	"time"

	"recordscan/internal/util"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type statusMsg struct {
	phase string
	meta  string
}

type doneMsg struct{}

type progModel struct {
	spinner spinner.Model
	phase   string
	events  []string
	done    bool
}

func initialModel() progModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
	return progModel{
		spinner: s,
		phase:   "Preparing scan...",
		events:  []string{},
	}
}

func (m progModel) Init() tea.Cmd { return m.spinner.Tick }

func (m progModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case statusMsg:
		m.phase = msg.phase
		if msg.meta != "" {
			m.events = append(m.events, msg.meta)
		}
		if len(m.events) > 8 {
			m.events = m.events[len(m.events)-8:]
		}
		return m, nil
	case doneMsg:
		m.done = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m progModel) View() string {
	phase := lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Render(m.phase)

	var b strings.Builder
	b.WriteString(util.Banner())
	if m.done {
		b.WriteString("[DONE] Scan completed\n")
	} else {
		b.WriteString(fmt.Sprintf("%s %s\n", m.spinner.View(), phase))
	}
	if len(m.events) > 0 {
		b.WriteString("\nRecent events:\n")
		for _, e := range m.events {
			b.WriteString("  - " + e + "\n")
		}
	}
	return b.String()
}

type Progress struct {
	program *tea.Program
	enabled bool
	done    chan struct{}
}

func NewProgress(enabled bool) *Progress {
	if !enabled {
		return &Progress{enabled: false}
	}
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	done := make(chan struct{})
	go func() {
		_, _ = p.Run()
		close(done)
	}()
	return &Progress{program: p, enabled: true, done: done}
}

func (p *Progress) Update(phase, meta string) {
	if !p.enabled {
		return
	}
	p.program.Send(statusMsg{phase: phase, meta: meta})
}

func (p *Progress) Done() {
	if !p.enabled {
		return
	}
	select {
	case <-p.done:
		return
	default:
	}
	p.program.Send(doneMsg{})
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
	}
}
