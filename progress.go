package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Progress tracks conversion state for the TUI. Writers call Add(bytes)
// from goroutines; the Bubble Tea model reads it on each frame.
type Progress struct {
	total       atomic.Int64
	written     atomic.Int64
	currentFile atomic.Value // string
	start       time.Time
	done        chan error
}

func NewProgress(total int64) *Progress {
	return &Progress{total: atomic.Int64{}, done: make(chan error, 1), start: time.Now()}
}

func (p *Progress) SetTotal(n int64)    { p.total.Store(n) }
func (p *Progress) SetFile(name string) { p.currentFile.Store(name) }
func (p *Progress) Add(n int64)         { p.written.Add(n) }
func (p *Progress) Finish(err error)    { p.done <- err }

// completed file entry for the view
type fileEntry struct {
	name string
	size int64
}

type progModel struct {
	progress  progress.Model
	tracker   *Progress
	completed []fileEntry
	current   string
	speed     float64
	err       error
	done      bool
	width     int
}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func newProgModel(tracker *Progress) progModel {
	return progModel{
		progress: progress.New(
			progress.WithDefaultGradient(),
			progress.WithWidth(50),
		),
		tracker: tracker,
	}
}

func (m progModel) Init() tea.Cmd { return tickCmd() }

func (m progModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		return m, nil

	case tickMsg:
		select {
		case err := <-m.tracker.done:
			m.done = true
			m.err = err
			final := float64(m.tracker.written.Load()) / float64(max(m.tracker.total.Load(), 1))
			return m, tea.Sequence(m.progress.SetPercent(final), tea.Quit)
		default:
		}

		written := m.tracker.written.Load()
		total := m.tracker.total.Load()
		cf, _ := m.tracker.currentFile.Load().(string)
		if cf != m.current {
			if m.current != "" {
				// previous file completed; estimate its size from written delta
				// (simplified — we could track per-file, but this is good enough)
			}
			m.current = cf
		}
		elapsed := time.Since(m.tracker.start).Seconds()
		if elapsed > 0 {
			m.speed = float64(written) / elapsed / 1e6 // MB/s
		}
		pct := float64(written) / float64(max(total, 1))
		cmd := m.progress.SetPercent(pct)
		return m, tea.Batch(cmd, tickCmd())

	}
	return m, nil
}

var (
	labelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	fileStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("213"))
	doneStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	speedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

func (m progModel) View() string {
	var b strings.Builder

	written := m.tracker.written.Load()
	total := m.tracker.total.Load()
	pct := float64(written) / float64(max(total, 1))

	b.WriteString(m.progress.View() + "\n")

	// stats line
	stats := fmt.Sprintf("%.1f%%  %s / %s",
		pct*100,
		humanBytes(written),
		humanBytes(total))
	if m.speed > 0 {
		stats += speedStyle.Render(fmt.Sprintf("  %.0f MB/s", m.speed))
	}
	b.WriteString(labelStyle.Render(stats) + "\n")

	// current file
	if m.current != "" && !m.done {
		b.WriteString(fileStyle.Render("▸ "+m.current) + "\n")
	}

	// result
	if m.done {
		if m.err != nil {
			b.WriteString(errStyle.Render(fmt.Sprintf("✗ %v", m.err)) + "\n")
		} else {
			b.WriteString(doneStyle.Render(fmt.Sprintf("✓ wrote %s in %s",
				humanBytes(written),
				time.Since(m.tracker.start).Round(time.Millisecond))) + "\n")
		}
	}

	return b.String()
}

func humanBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// runProgressTUI starts a Bubble Tea program for progress display.
// Returns the program; call WaitForDone after the conversion finishes.
// When stderr is not a TTY, returns nil (no TUI).
func runProgressTUI(tracker *Progress) *tea.Program {
	if !isTerminal(os.Stderr) {
		return nil
	}
	m := newProgModel(tracker)
	p := tea.NewProgram(m, tea.WithOutput(os.Stderr))
	go func() {
		_, _ = p.Run()
	}()
	return p
}

// WaitForDone blocks until the TUI finishes (or is nil).
func WaitForDone(p *tea.Program) {
	if p == nil {
		return
	}
	p.Wait()
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// suppress unused warnings
var _ = sort.Strings
