package report

import (
	"embed"
	"io/fs"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

//go:embed web/dist
var distFS embed.FS

type spaFS struct {
	fs http.FileSystem
}

func (s *spaFS) Open(name string) (http.File, error) {
	f, err := s.fs.Open(name)
	if err != nil {
		return s.fs.Open("index.html")
	}
	return f, nil
}

func StartWebServer(addr string) error {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// API routes
	api := r.Group("/api")
	api.GET("/reports", handleListReports)
	api.GET("/reports/:id", handleReportDetail)

	// Static files + SPA fallback
	distFS, err := fs.Sub(distFS, "web/dist")
	if err != nil {
		logrus.Fatalf("sub fs: %v", err)
	}

	fileServer := http.FileServer(&spaFS{fs: http.FS(distFS)})
	r.NoRoute(gin.WrapH(fileServer))

	logrus.Infof("web server listening on http://%s", addr)
	return r.Run(addr)
}

func handleListReports(c *gin.Context) {
	reports, err := ListReports()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	items := make([]map[string]any, 0, len(reports))
	for i := range reports {
		items = append(items, map[string]any{
			"id":           reports[i].ID,
			"sha256":       reports[i].SHA256,
			"sample_name":  reports[i].SampleName,
			"file_type":    reports[i].FileType,
			"analysis_env": reports[i].AnalysisEnv,
			"created_at":   reports[i].CreatedAt,
			"verdict":      reports[i].Verdict,
		})
	}

	c.JSON(http.StatusOK, items)
}

func handleReportDetail(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid report id"})
		return
	}

	report, err := GetReport(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}

	c.JSON(http.StatusOK, report)
}
