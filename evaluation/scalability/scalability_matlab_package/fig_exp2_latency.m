function fig_exp2_latency()
%FIG_EXP2_LATENCY  Policy engine: offered rate vs service p50/p95/p99 latency.
% Reads exp2_evaluator_scaling.csv. Marks the empirical saturation knee.
% Self-contained.

% ---- STYLE ----
col_p50=[0.031 0.318 0.612]; col_p95=[0.192 0.510 0.741]; col_p99=[0.902 0.333 0.051];
knee=27.5;   % between last-stable (20) and overloaded (30); edit as desired
lw=1.8; ms=5; fsize=11; figsize=[0 0 6.0 3.8];
% ---------------
here=fileparts(mfilename('fullpath'));
T=readtable(fullfile(here,'exp2_evaluator_scaling.csv'));
r=T.offered_rate_eval_s;
fig=figure('Units','inches','Position',figsize,'Color','w'); ax=axes(fig); hold(ax,'on');
plot(ax,r,T.service_p50_ms,'-o','Color',col_p50,'LineWidth',lw,'MarkerFaceColor',col_p50,'MarkerSize',ms,'DisplayName','p50');
plot(ax,r,T.service_p95_ms,'--s','Color',col_p95,'LineWidth',lw,'MarkerFaceColor',col_p95,'MarkerSize',ms,'DisplayName','p95');
plot(ax,r,T.service_p99_ms,'-.^','Color',col_p99,'LineWidth',lw,'MarkerFaceColor',col_p99,'MarkerSize',ms,'DisplayName','p99');
xline(ax,knee,':','saturation knee','Color',[0.4 0.4 0.4],'LineWidth',1.2,'FontSize',fsize-3);
xlabel(ax,'Offered rate (eval/s)','FontSize',fsize); ylabel(ax,'Service latency (ms)','FontSize',fsize);
set(ax,'YScale','log'); grid(ax,'on'); ax.GridAlpha=0.25; box(ax,'on'); ax.FontSize=fsize-1;
legend(ax,'Location','northwest','Box','off','FontSize',fsize-2);
title(ax,'Policy-engine latency approaching saturation (log y)','FontSize',fsize-1); hold(ax,'off');
exportgraphics(fig,fullfile(here,'exp2_latency.pdf'),'ContentType','vector');
exportgraphics(fig,fullfile(here,'exp2_latency.png'),'Resolution',200); close(fig);
end
