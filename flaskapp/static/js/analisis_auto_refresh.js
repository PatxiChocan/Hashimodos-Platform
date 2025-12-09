window.addEventListener("load", function () {
  const params = new URLSearchParams(window.location.search);
  const autoRefresh = params.get("auto_refresh");
  const lastKnown = parseInt(params.get("last_known") || "0", 10);

  const scanDataEl = document.getElementById("scan-data");
  let currentLatest = NaN;

  if (scanDataEl) {
    currentLatest = parseInt(scanDataEl.dataset.currentLatest || "0", 10);
  }

  // Solo auto-refrescar si la URL trae ?auto_refresh=1
  if (autoRefresh === "1") {
    console.log(
      "Auto-refresh activado. last_known=",
      lastKnown,
      " current_latest=",
      currentLatest
    );

    // Si ya hay un análisis nuevo (ID mayor), desactivamos el auto-refresh
    if (!isNaN(lastKnown) && !isNaN(currentLatest) && currentLatest > lastKnown) {
      console.log("Nuevo análisis detectado. Desactivando auto-refresh.");

      // Construimos una URL sin auto_refresh ni last_known
      const newUrl = new URL(window.location.href);
      newUrl.searchParams.delete("auto_refresh");
      newUrl.searchParams.delete("last_known");

      // Marcamos que el escaneo ha terminado correctamente
      newUrl.searchParams.set("scan_done", "1");

      // Recargamos una sola vez con los parámetros limpios
      window.location.href = newUrl.toString();
      return;
    }

    // Si todavía no hay análisis nuevo, seguimos refrescando periódicamente
    setTimeout(function () {
      console.log("Refrescando página para comprobar nuevo análisis...");
      window.location.reload();
    }, 5000); // 5 segundos
  } else {
    console.log("Auto-refresh desactivado para esta página.");
  }
});
