function fig_scal_03_physical()
%FIG_SCAL_03_PHYSICAL  Experiment 3: real-xApp concurrent isolation.
% Reads physical_scaling.csv (one row per concurrency level K) and plots the
% median and p95 attack-onset-to-verified-unreachable latency against K, with
% the median-to-p95 spread shown as an error bar. Exports PDF + PNG next to
% this file.
%
% Edit the STYLE block below to restyle. Self-contained: no external helpers.

% ---- STYLE (edit freely) ----
col_med = [0.031 0.318 0.612];   % dark blue
col_p95 = [0.902 0.333 0.051];   % orange
lw      = 1.8;
ms      = 7;
fsize   = 11;
figsize = [0 0 6.2 3.8];          % inches
% ------------------------------

here = fileparts(mfilename('fullpath'));
T = readtable(fullfile(here, 'physical_scaling.csv'));

fig = figure('Units','inches','Position',figsize,'Color','w');
ax = axes(fig); hold(ax,'on');

% median with an error bar reaching up to p95
errorbar(ax, T.K, T.net_med_s, zeros(height(T),1), T.net_p95_s - T.net_med_s, ...
    '-o', 'Color',col_med, 'LineWidth',lw, 'MarkerFaceColor',col_med, ...
    'MarkerSize',ms, 'CapSize',6, 'DisplayName','median (bar to p95)');
plot(ax, T.K, T.net_p95_s, '--s', 'Color',col_p95, 'LineWidth',lw, ...
    'MarkerFaceColor',col_p95, 'MarkerSize',ms-1, 'DisplayName','p95');

xlabel(ax, 'Concurrent compromised xApps K', 'FontSize',fsize);
ylabel(ax, {'Attack-onset \rightarrow verified','unreachable (s)'}, 'FontSize',fsize);
xlim(ax, [0.5 max(T.K)+0.5]); ylim(ax, [0 max(T.net_p95_s)*1.15]);
xticks(ax, T.K);
grid(ax,'on'); ax.GridAlpha = 0.25; box(ax,'on');
ax.FontSize = fsize - 1;
legend(ax, 'Location','northwest', 'Box','off', 'FontSize',fsize-2);
% annotate 100% containment
text(ax, 0.98, 0.06, 'All 26 attempts contained (K=1..4)', ...
    'Units','normalized', 'HorizontalAlignment','right', ...
    'FontSize',fsize-3, 'Color',[0.4 0.4 0.4]);
hold(ax,'off');

exportgraphics(fig, fullfile(here,'scal_physical_latency.pdf'), 'ContentType','vector');
exportgraphics(fig, fullfile(here,'scal_physical_latency.png'), 'Resolution',200);
close(fig);
end
