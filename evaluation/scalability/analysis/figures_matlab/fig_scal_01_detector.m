function fig_scal_01_detector()
%FIG_SCAL_01_DETECTOR  Experiment 1: detector computational scalability.
% Reads detector_scaling.csv (one row per N independent detector contexts)
% and plots mean / p95 / max per-cycle scoring latency against N, with the
% 1 Hz (1000 ms) deadline noted. Exports PDF + PNG next to this file.
%
% Edit the STYLE block below to restyle. Self-contained: no external helpers.

% ---- STYLE (edit freely) ----
col_mean = [0.031 0.318 0.612];   % dark blue
col_p95  = [0.192 0.510 0.741];   % mid blue
col_max  = [0.902 0.333 0.051];   % orange
lw       = 1.6;
ms       = 5;
fsize    = 11;
figsize  = [0 0 6.2 3.8];         % inches
% ------------------------------

here = fileparts(mfilename('fullpath'));
T = readtable(fullfile(here, 'detector_scaling.csv'));

fig = figure('Units','inches','Position',figsize,'Color','w');
ax = axes(fig); hold(ax,'on');

plot(ax, T.N_contexts, T.mean_ms, '-o', 'Color',col_mean, 'LineWidth',lw, ...
    'MarkerFaceColor',col_mean, 'MarkerSize',ms, 'DisplayName','mean');
plot(ax, T.N_contexts, T.p95_ms,  '--s', 'Color',col_p95,  'LineWidth',lw, ...
    'MarkerFaceColor',col_p95, 'MarkerSize',ms, 'DisplayName','p95');
plot(ax, T.N_contexts, T.max_ms,  ':^', 'Color',col_max,  'LineWidth',lw, ...
    'MarkerFaceColor',col_max, 'MarkerSize',ms, 'DisplayName','max');

xlabel(ax, 'Independent detector contexts N', 'FontSize',fsize);
ylabel(ax, 'Detector cycle latency (ms)', 'FontSize',fsize);
xlim(ax, [0.5 max(T.N_contexts)+0.5]);
xticks(ax, T.N_contexts);
grid(ax,'on'); ax.GridAlpha = 0.25; box(ax,'on');
ax.FontSize = fsize - 1;
legend(ax, 'Location','northwest', 'Box','off', 'FontSize',fsize-2);
text(ax, 0.98, 0.05, '1 Hz deadline = 1000 ms (never approached)', ...
    'Units','normalized', 'HorizontalAlignment','right', ...
    'FontSize',fsize-3, 'Color',[0.4 0.4 0.4]);
hold(ax,'off');

exportgraphics(fig, fullfile(here,'scal_detector_cycle.pdf'), 'ContentType','vector');
exportgraphics(fig, fullfile(here,'scal_detector_cycle.png'), 'Resolution',200);
close(fig);
end
