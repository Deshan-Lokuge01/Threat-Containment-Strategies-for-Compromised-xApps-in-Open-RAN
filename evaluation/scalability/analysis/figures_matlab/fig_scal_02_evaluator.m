function fig_scal_02_evaluator()
%FIG_SCAL_02_EVALUATOR  Experiment 2: evaluator open-loop scalability.
% Reads evaluator_scaling.csv (one row per offered rate) and plots the
% deadline-miss rate against offered evaluation rate, with shaded
% stable / marginal / saturated bands. Exports PDF + PNG next to this file.
%
% Edit the STYLE block below to restyle. Self-contained: no external helpers.

% ---- STYLE (edit freely) ----
col_line   = [0.031 0.318 0.612];   % dark blue
band_stable    = [0.780 0.914 0.753];
band_marginal  = [0.996 0.890 0.569];
band_saturated = [0.988 0.682 0.569];
stable_max   = 27.5;   % green up to here
marginal_max = 32.5;   % yellow up to here, red beyond
lw      = 1.8;
ms      = 6;
fsize   = 11;
figsize = [0 0 6.2 3.8];           % inches
% ------------------------------

here = fileparts(mfilename('fullpath'));
T = readtable(fullfile(here, 'evaluator_scaling.csv'));
rmin = min(T.offered_rate_eval_s); rmax = max(T.offered_rate_eval_s);

fig = figure('Units','inches','Position',figsize,'Color','w');
ax = axes(fig); hold(ax,'on');

shade(ax, rmin-1, stable_max,   band_stable,    'stable');
shade(ax, stable_max, marginal_max, band_marginal,  'marginal');
shade(ax, marginal_max, rmax+1,  band_saturated, 'saturated');

plot(ax, T.offered_rate_eval_s, T.miss_rate_pct, '-o', 'Color',col_line, ...
    'LineWidth',lw, 'MarkerFaceColor',col_line, 'MarkerSize',ms, ...
    'HandleVisibility','off');

xlabel(ax, 'Offered evaluation rate (eval/s)', 'FontSize',fsize);
ylabel(ax, 'Deadline-miss rate (%)', 'FontSize',fsize);
xlim(ax, [rmin-1 rmax+1]); ylim(ax, [-3 100]);
grid(ax,'on'); ax.GridAlpha = 0.25; box(ax,'on');
ax.FontSize = fsize - 1;
legend(ax, 'Location','west', 'Box','off', 'FontSize',fsize-2);
hold(ax,'off');

exportgraphics(fig, fullfile(here,'scal_evaluator_miss.pdf'), 'ContentType','vector');
exportgraphics(fig, fullfile(here,'scal_evaluator_miss.png'), 'Resolution',200);
close(fig);
end

function shade(ax, x0, x1, rgb, name)
patch(ax, [x0 x1 x1 x0], [-3 -3 100 100], rgb, 'EdgeColor','none', ...
    'FaceAlpha',0.5, 'DisplayName',name);
end
